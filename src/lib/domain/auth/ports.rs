use async_trait::async_trait;
use sqlx::Error as SqlxError;
use uuid::Uuid;

use crate::domain::auth::models::User;
use crate::domain::auth::models::email_verification_token::EmailVerificationToken;
use crate::domain::auth::models::password_reset_tokens::{
    ForgotPasswordError, ForgotPasswordRequest, PasswordResetToken, ResetPasswordError,
    ResetPasswordRequest,
};
use crate::domain::auth::models::refresh_token::{
    RefreshToken, RefreshTokenError, RefreshTokenRequest,
};
use crate::domain::auth::models::user::{
    FindUserError, LoginError, LoginUserRequest, RegisterUserError, RegisterUserRequest,
    VerifyEmailError, VerifyEmailRequest,
};

#[async_trait]
pub trait AuthService: Send + Sync + 'static {
    async fn register_user(
        &self,
        req: &RegisterUserRequest,
    ) -> Result<(User, String, String), RegisterUserError>;

    async fn login(&self, req: &LoginUserRequest) -> Result<(User, String, String), LoginError>;

    async fn verify_email(&self, req: &VerifyEmailRequest<'_>) -> Result<(), VerifyEmailError>;

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<User>, FindUserError>;

    async fn get_user_from_token(&self, token: &str) -> Result<Option<User>, LoginError>;

    async fn generate_token_for_user(&self, user_id: &Uuid) -> Result<String, FindUserError>;

    async fn refresh_token(&self, req: &RefreshTokenRequest) -> Result<String, RefreshTokenError>;

    async fn forgot_password(&self, req: &ForgotPasswordRequest)
    -> Result<(), ForgotPasswordError>;
    async fn reset_password(&self, req: &ResetPasswordRequest) -> Result<(), ResetPasswordError>;
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create(
        &self,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<User, SqlxError>;

    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>, SqlxError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, SqlxError>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, SqlxError>;

    async fn update(
        &self,
        id: Uuid,
        username: Option<&str>,
        email: Option<&str>,
        bio: Option<&str>,
        image: Option<&str>,
    ) -> Result<Option<User>, SqlxError>;

    async fn update_password(
        &self,
        user_id: Uuid,
        new_password_hash: &str,
    ) -> Result<(), SqlxError>;
}

#[async_trait]
pub trait EmailVerificationRepository: Send + Sync {
    async fn create_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<EmailVerificationToken, SqlxError>;

    async fn find_by_token(&self, token: &str)
    -> Result<Option<EmailVerificationToken>, SqlxError>;

    async fn delete_token(&self, token: &str) -> Result<(), SqlxError>;

    async fn verify_user_email(&self, user_id: Uuid) -> Result<(), SqlxError>;
}

#[async_trait]
pub trait UserNotfier: Send + Sync {
    async fn send_verification_email(
        &self,
        to_email: &str,
        username: &str,
        verification_token: &str,
    ) -> Result<(), anyhow::Error>;

    async fn send_password_reset_email(
        &self,
        to_email: &str,
        username: &str,
        reset_token: &str,
    ) -> Result<(), anyhow::Error>;
}

#[async_trait]
pub trait PasswordResetRepository: Send + Sync {
    async fn create_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<PasswordResetToken, SqlxError>;

    async fn find_by_token(&self, token: &str) -> Result<Option<PasswordResetToken>, SqlxError>;

    async fn delete_token(&self, token: &str) -> Result<(), SqlxError>;

    async fn delete_all_user_tokens(&self, user_id: Uuid) -> Result<(), SqlxError>;
}

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    async fn create_token(&self, user_id: Uuid, token: &str) -> Result<RefreshToken, SqlxError>;

    async fn find_by_token(&self, token: &str) -> Result<Option<RefreshToken>, SqlxError>;

    async fn update_last_used(&self, token: &str) -> Result<(), SqlxError>;

    async fn delete_token(&self, token: &str) -> Result<(), SqlxError>;

    async fn delete_all_user_tokens(&self, user_id: Uuid) -> Result<(), SqlxError>;
}
