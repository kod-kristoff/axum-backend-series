use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub bio: Option<String>,
    pub image: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterUserRequest {
    pub user: RegisterUserData,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterUserData {
    #[validate(length(
        min = 3,
        max = 50,
        message = "Username must be between 3 and 50 characters"
    ))]
    pub username: String,

    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterUserError {
    #[error("user with email '{email}' already exists")]
    DuplicateEmail { email: String },
    #[error("user with username '{username}' already exists")]
    DuplicateUsername { username: String },
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

#[derive(Debug, Deserialize)]
pub struct LoginUserRequest {
    pub user: LoginUserData,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginUserData {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("that combination of user and password doesn't exist")]
    Unauthorized,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}
#[derive(Debug, thiserror::Error)]
pub enum FindUserError {
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

#[derive(Debug)]
pub struct VerifyEmailRequest<'a> {
    pub token: &'a String,
}
#[derive(Debug, thiserror::Error)]
pub enum VerifyEmailError {
    #[error("email verification token is expired")]
    IsExpired,
    #[error("email verification token is not found")]
    NotFound,
    #[error(transparent)]
    Unknown(#[from] anyhow::Error),
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(
        min = 3,
        max = 50,
        message = "Username must be between 3 and 50 characters"
    ))]
    pub username: String,

    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(length(
        min = 3,
        max = 50,
        message = "Username must be between 3 and 50 characters"
    ))]
    pub username: Option<String>,

    #[validate(email(message = "Invalid email format"))]
    pub email: Option<String>,

    #[validate(length(max = 500, message = "Bio cannot exceed 500 characters"))]
    pub bio: Option<String>,

    #[validate(url(message = "Image must be a valid URL"))]
    pub image: Option<String>,
}
