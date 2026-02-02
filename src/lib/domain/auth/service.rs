use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::domain::auth::{
    models::{
        User,
        password_reset_tokens::{
            ForgotPasswordError, ForgotPasswordRequest, ResetPasswordError, ResetPasswordRequest,
        },
        refresh_token::{LogoutRequest, RefreshTokenError, RefreshTokenRequest},
        user::{
            FindUserError, LoginError, LoginUserRequest, LogoutError, RegisterUserError,
            RegisterUserRequest, VerifyEmailError, VerifyEmailRequest,
        },
    },
    ports::{
        AuthService, EmailVerificationRepository, PasswordResetRepository, RefreshTokenRepository,
        UserNotfier, UserRepository,
    },
    shared::{
        jwt::{generate_token, validate_token},
        password::{hash_password, verify_password},
        token_generator::{generate_refresh_token, generate_verification_token},
    },
};

pub struct Service {
    user_repository: Arc<dyn UserRepository>,
    email_verification_repository: Arc<dyn EmailVerificationRepository>,
    password_reset_repository: Arc<dyn PasswordResetRepository>,
    refresh_token_repository: Arc<dyn RefreshTokenRepository>,
    user_notifier: Arc<dyn UserNotfier>,
}

impl Service {
    pub fn new(
        user_repository: Arc<dyn UserRepository>,
        email_verification_repository: Arc<dyn EmailVerificationRepository>,
        password_reset_repository: Arc<dyn PasswordResetRepository>,
        refresh_token_repository: Arc<dyn RefreshTokenRepository>,
        user_notifier: Arc<dyn UserNotfier>,
    ) -> Self {
        Self {
            user_repository,
            email_verification_repository,
            password_reset_repository,
            refresh_token_repository,
            user_notifier,
        }
    }
}

#[async_trait]
impl AuthService for Service {
    async fn register_user(
        &self,
        req: &RegisterUserRequest,
    ) -> Result<(User, String, String), RegisterUserError> {
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
        let access_token =
            generate_token(&user.id, &jwt_secret).map_err(Into::<anyhow::Error>::into)?;

        // Generate refresh token
        let refresh_token = generate_refresh_token();

        // Save refresh token
        self.refresh_token_repository
            .create_token(user.id, &refresh_token)
            .await
            .map_err(|err| RegisterUserError::Unknown(err.into()))?;
        Ok((user, access_token, refresh_token))
    }

    async fn login(&self, req: &LoginUserRequest) -> Result<(User, String, String), LoginError> {
        // Find user by email
        let user = self
            .user_repository
            .find_by_email(&req.user.email)
            .await
            .map_err(|err| LoginError::Unknown(err.into()))?
            .ok_or(LoginError::Unauthorized)?;

        // Verify password
        // move the verifying to another thread to not degrade performance for other tasks
        let password_valid = tokio::task::spawn_blocking({
            let password = req.user.password.clone();
            let password_hash = user.password_hash.clone();
            move || verify_password(&password, &password_hash)
        })
        .await
        // JoinError
        .map_err(|err| LoginError::Unknown(err.into()))?
        // BrcyptError
        .map_err(|err| LoginError::Unknown(err.into()))?;

        if !password_valid {
            return Err(LoginError::Unauthorized);
        }

        // Generate JWT token
        let jwt_secret =
            std::env::var("JWT_SECRET").map_err(|err| LoginError::Unknown(err.into()))?;
        let access_token =
            generate_token(&user.id, &jwt_secret).map_err(|err| LoginError::Unknown(err.into()))?;

        // Generate refresh token
        let refresh_token = generate_refresh_token();

        // Save refresh token
        self.refresh_token_repository
            .create_token(user.id, &refresh_token)
            .await
            .map_err(|err| LoginError::Unknown(err.into()))?;
        Ok((user, access_token, refresh_token))
    }

    async fn logout(&self, req: &LogoutRequest) -> Result<(), LogoutError> {
        self.refresh_token_repository
            .delete_token(&req.refresh_token)
            .await
            .map_err(|err| LogoutError::Unknown(err.into()))?;
        Ok(())
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

        let claims = validate_token(token, &jwt_secret).map_err(|_| LoginError::Unauthorized)?;

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

    async fn refresh_token(
        &self,
        req: &RefreshTokenRequest,
    ) -> Result<(String, String), RefreshTokenError> {
        // Look up the refresh token in database
        let refresh_token = self
            .refresh_token_repository
            .find_by_token(&req.refresh_token)
            .await
            .map_err(|err| RefreshTokenError::Unknown(err.into()))?
            .ok_or(RefreshTokenError::Unauthorized)?;

        // Check if token has expired
        if refresh_token.is_expired() {
            // Token is expired, delete it and reject
            let _ = self
                .refresh_token_repository
                .delete_token(&req.refresh_token)
                .await;
            return Err(RefreshTokenError::Unauthorized);
        }

        // REUSE DETECTION - Check if token was already used
        if refresh_token.is_used {
            // SECURITY BREACH DETECTED"
            // Someone is trying to use an old token
            // This means the token was likely stolen

            eprintln!("TOKEN REUSE DETECTED!");
            eprintln!("Token: {}", &req.refresh_token);
            eprintln!("User ID: {}", refresh_token.user_id);
            eprintln!("Originally used at: {:?}", refresh_token.used_at);

            // Nuclear option: Delete ALL user's refresh tokens
            // Force them to login again
            self.refresh_token_repository
                .delete_all_user_tokens(refresh_token.user_id)
                .await
                .map_err(|err| RefreshTokenError::Unknown(err.into()))?;

            // Get user info for email
            let user = self
                .user_repository
                .find_by_id(refresh_token.user_id)
                .await
                .map_err(|err| RefreshTokenError::Unknown(err.into()))?
                .ok_or_else(|| {
                    RefreshTokenError::Unknown(anyhow::anyhow!(
                        "User with id '{}' is missing,",
                        refresh_token.user_id
                    ))
                })?;

            // Send security alert email
            if let Err(e) = self
                .user_notifier
                .send_security_alert(&user.email, &user.username)
                .await
            {
                eprintln!("Failed to send security alert email: {}", e);
                // Don't fail the request if email fails
            }

            return Err(RefreshTokenError::Unauthorized);
        }

        // Mark the old token as used (consumed)
        self.refresh_token_repository
            .mark_token_as_used(&req.refresh_token)
            .await
            .map_err(|err| RefreshTokenError::Unknown(err.into()))?;

        // Generate NEW refresh token with rotation
        let new_refresh_token = generate_refresh_token();

        // Save the new refresh token
        self.refresh_token_repository
            .create_token(refresh_token.user_id, &new_refresh_token)
            .await
            .map_err(|err| RefreshTokenError::Unknown(err.into()))?;

        // Generate new access token
        let jwt_secret =
            std::env::var("JWT_SECRET").map_err(|err| RefreshTokenError::Unknown(err.into()))?;
        let access_token = generate_token(&refresh_token.user_id, &jwt_secret)
            .map_err(|err| RefreshTokenError::Unknown(err.into()))?;

        Ok((access_token, new_refresh_token))
    }

    async fn forgot_password(
        &self,
        req: &ForgotPasswordRequest,
    ) -> Result<(), ForgotPasswordError> {
        // Validate email format
        // req.validate().map_err(|_| ResetPasswordError::BAD_REQUEST)?;

        // Look up user by email
        let user = self
            .user_repository
            .find_by_email(&req.email)
            .await
            .map_err(|err| ForgotPasswordError::Unknown(err.into()))?;

        // SECURITY: Always return success even if email doesn't exist
        // This prevents attackers from discovering which emails are registered
        if user.is_none() {
            return Ok(());
        }

        let user = user.unwrap();

        // Generate reset token
        let reset_token = generate_verification_token();
        let expires_at = Utc::now() + Duration::hours(1); // 1 hour expiration

        // Save token to database
        self.password_reset_repository
            .create_token(user.id, &reset_token, expires_at)
            .await
            .map_err(|err| ForgotPasswordError::Unknown(err.into()))?;

        // Send reset email
        self.user_notifier
            .send_password_reset_email(&user.email, &user.username, &reset_token)
            .await
            .map_err(|err| {
                eprintln!("Failed to send password reset email: {}", err);
                ForgotPasswordError::Unknown(err)
            })?;

        Ok(())
    }

    // Handler for actually resetting the password
    async fn reset_password(&self, req: &ResetPasswordRequest) -> Result<(), ResetPasswordError> {
        // Validate new password
        // req.validate().map_err(|_| ResetPasswordError::BAD_REQUEST)?;

        // Look up token
        let reset_token = self
            .password_reset_repository
            .find_by_token(&req.token)
            .await
            .map_err(|err| ResetPasswordError::Unknown(err.into()))?
            .ok_or(ResetPasswordError::TokenNotFound)?;

        // Check expiration
        if reset_token.is_expired() {
            // Clean up expired token
            self.password_reset_repository
                .delete_token(&req.token)
                .await
                .map_err(|err| ResetPasswordError::Unknown(err.into()))?;

            return Err(ResetPasswordError::TokenIsExpired);
        }

        // Hash new password
        let new_password_hash = hash_password(&req.new_password)
            .map_err(|err| ResetPasswordError::Unknown(err.into()))?;

        // Update user password
        self.user_repository
            .update_password(reset_token.user_id, &new_password_hash)
            .await
            .map_err(|err| ResetPasswordError::Unknown(err.into()))?;

        // Delete ALL reset tokens for this user (invalidate any other pending requests)
        self.password_reset_repository
            .delete_all_user_tokens(reset_token.user_id)
            .await
            .map_err(|err| ResetPasswordError::Unknown(err.into()))?;

        Ok(())
    }
}
