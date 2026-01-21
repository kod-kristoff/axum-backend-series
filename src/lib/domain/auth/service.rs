use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::domain::auth::{
    models::{
        User,
        user::{
            FindUserError, LoginError, LoginUserRequest, RegisterUserError, RegisterUserRequest,
            VerifyEmailError, VerifyEmailRequest,
        },
    },
    ports::{AuthService, EmailVerificationRepository, UserNotfier, UserRepository},
    shared::{
        jwt::{generate_token, validate_token},
        password::{hash_password, verify_password},
        token_generator::generate_verification_token,
    },
};

pub struct Service {
    user_repository: Arc<dyn UserRepository>,
    email_verification_repository: Arc<dyn EmailVerificationRepository>,
    user_notifier: Arc<dyn UserNotfier>,
}

impl Service {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        email_verification_repository: Arc<dyn EmailVerificationRepository>,
        user_notifier: Arc<dyn UserNotfier>,
    ) -> Self {
        Self {
            user_repository,
            email_verification_repository,
            user_notifier,
        }
    }
}

#[async_trait]
impl AuthService for Service {
    async fn register_user(
        &self,
        req: &RegisterUserRequest,
    ) -> Result<(User, String), RegisterUserError> {
        // Check if user already exists
        if self
            .user_repository
            .find_by_email(&req.user.email)
            .await
            .map_err(|err| RegisterUserError::Unknown(err.into()))?
            .is_some()
        {
            return Err(RegisterUserError::DuplicateEmail {
                email: req.user.email.clone(),
            });
        }

        if self
            .user_repository
            .find_by_username(&req.user.username)
            .await
            .map_err(|err| RegisterUserError::Unknown(err.into()))?
            .is_some()
        {
            return Err(RegisterUserError::DuplicateUsername {
                username: req.user.username.clone(),
            });
        }

        // Hash the password
        let password_hash = hash_password(&req.user.password)
            .map_err(|err| RegisterUserError::Unknown(err.into()))?;

        // Create user in database
        let user = self
            .user_repository
            .create(&req.user.username, &req.user.email, &password_hash)
            .await
            .map_err(|err| RegisterUserError::Unknown(err.into()))?;

        // Generate verification token
        let verification_token = generate_verification_token();
        let expires_at = Utc::now() + Duration::hours(24);

        // Save token to database
        self.email_verification_repository
            .create_token(user.id, &verification_token, expires_at)
            .await
            .map_err(|err| RegisterUserError::Unknown(err.into()))?;

        // Send verification email
        self.user_notifier
            .send_verification_email(&user.email, &user.username, &verification_token)
            .await
            .map_err(|e| {
                eprintln!("Failed to send verification email: {}", e);
                e
            })?;

        // Generate JWT token
        let jwt_secret = std::env::var("JWT_SECRET").map_err(Into::<anyhow::Error>::into)?;
        let token = generate_token(&user.id, &jwt_secret).map_err(Into::<anyhow::Error>::into)?;
        Ok((user, token))
    }

    async fn login(&self, req: &LoginUserRequest) -> Result<(User, String), LoginError> {
        // Find user by email
        let user = self
            .user_repository
            .find_by_email(&req.user.email)
            .await
            .map_err(|err| LoginError::Unknown(err.into()))?
            .ok_or(LoginError::Unauthorized)?;

        // Verify password
        let password_valid = verify_password(&req.user.password, &user.password_hash)
            .map_err(|err| LoginError::Unknown(err.into()))?;

        if !password_valid {
            return Err(LoginError::Unauthorized);
        }

        // Generate JWT token
        let jwt_secret =
            std::env::var("JWT_SECRET").map_err(|err| LoginError::Unknown(err.into()))?;
        let token =
            generate_token(&user.id, &jwt_secret).map_err(|err| LoginError::Unknown(err.into()))?;
        Ok((user, token))
    }

    async fn verify_email(&self, req: &VerifyEmailRequest<'_>) -> Result<(), VerifyEmailError> {
        // Look up the token in database
        let verification_token = self
            .email_verification_repository
            .find_by_token(req.token)
            .await
            .map_err(|err| VerifyEmailError::Unknown(err.into()))?
            .ok_or(VerifyEmailError::NotFound)?;

        // Check if expired
        if verification_token.is_expired() {
            // Clean up expired token
            self.email_verification_repository
                .delete_token(req.token)
                .await
                .map_err(|err| VerifyEmailError::Unknown(err.into()))?;

            return Err(VerifyEmailError::IsExpired);
        }

        // Mark user as verified
        self.email_verification_repository
            .verify_user_email(verification_token.user_id)
            .await
            .map_err(|err| VerifyEmailError::Unknown(err.into()))?;

        // Delete token (single-use)
        self.email_verification_repository
            .delete_token(req.token)
            .await
            .map_err(|err| VerifyEmailError::Unknown(err.into()))?;
        Ok(())
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<User>, FindUserError> {
        self.user_repository
            .find_by_id(user_id)
            .await
            .map_err(|err| FindUserError::Unknown(err.into()))
    }

    async fn get_user_from_token(&self, token: &str) -> Result<Option<User>, LoginError> {
        // Validate JWT token
        let jwt_secret =
            std::env::var("JWT_SECRET").map_err(|err| LoginError::Unknown(err.into()))?;

        let claims = validate_token(&token, &jwt_secret).map_err(|_| LoginError::Unauthorized)?;

        // Get user from database
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| LoginError::Unauthorized)?;

        let user = self
            .user_repository
            .find_by_id(user_id)
            .await
            .map_err(|err| LoginError::Unknown(err.into()))?;
        Ok(user)
    }

    async fn generate_token_for_user(&self, user_id: &Uuid) -> Result<String, FindUserError> {
        // Generate fresh JWT token
        let jwt_secret =
            std::env::var("JWT_SECRET").map_err(|err| FindUserError::Unknown(err.into()))?;
        let token = generate_token(user_id, &jwt_secret)
            .map_err(|err| FindUserError::Unknown(err.into()))?;
        Ok(token)
    }
}
