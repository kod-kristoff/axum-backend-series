use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;

use crate::domain::auth::models::{
    password_reset_tokens::{ForgotPasswordError, ResetPasswordError},
    refresh_token::RefreshTokenError,
    user::{FindUserError, LoginError, LogoutError, RegisterUserError, VerifyEmailError},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    BadRequest(String),
    Conflict(String),
    Gone,
    InternalServerError(String),
    NotFound,
    Unauthorized,
    UnprocessableEntity(String),
}

impl From<RegisterUserError> for ApiError {
    fn from(err: RegisterUserError) -> Self {
        match err {
            RegisterUserError::DuplicateEmail { email } => {
                Self::Conflict(format!("user with email {} already exists", email))
            }
            RegisterUserError::DuplicateUsername { username } => {
                Self::Conflict(format!("user with username {} already exists", username))
            }
            RegisterUserError::Unknown(cause) => {
                eprintln!("{:?}", cause);
                Self::InternalServerError("Internal server error".to_string())
            }
        }
    }
}

impl From<LoginError> for ApiError {
    fn from(err: LoginError) -> Self {
        match err {
            LoginError::Unauthorized => Self::Unauthorized,
            LoginError::Unknown(cause) => {
                eprintln!("{:?}", cause);
                Self::InternalServerError("Internal Server Error".to_string())
            }
        }
    }
}

impl From<FindUserError> for ApiError {
    fn from(err: FindUserError) -> Self {
        match err {
            FindUserError::Unknown(cause) => {
                eprintln!("{:?}", cause);
                Self::InternalServerError("Internal Server Error".to_string())
            }
        }
    }
}

impl From<VerifyEmailError> for ApiError {
    fn from(err: VerifyEmailError) -> Self {
        match err {
            VerifyEmailError::IsExpired => Self::Gone,
            VerifyEmailError::NotFound => Self::NotFound,
            VerifyEmailError::Unknown(cause) => {
                eprintln!("{:?}", cause);
                Self::InternalServerError("Internal Server Error".to_string())
            }
        }
    }
}

impl From<ForgotPasswordError> for ApiError {
    fn from(err: ForgotPasswordError) -> Self {
        match err {
            ForgotPasswordError::Unknown(cause) => {
                eprintln!("{:?}", cause);
                Self::InternalServerError("Internal Server Error".to_string())
            }
        }
    }
}

impl From<ResetPasswordError> for ApiError {
    fn from(err: ResetPasswordError) -> Self {
        match err {
            ResetPasswordError::TokenIsExpired => Self::Gone,
            ResetPasswordError::TokenNotFound => Self::NotFound,
            ResetPasswordError::Unknown(cause) => {
                eprintln!("{:?}", cause);
                Self::InternalServerError("Internal Server Error".to_string())
            }
        }
    }
}

impl From<RefreshTokenError> for ApiError {
    fn from(err: RefreshTokenError) -> Self {
        match err {
            RefreshTokenError::Unauthorized => Self::Unauthorized,
            RefreshTokenError::Unknown(cause) => {
                eprintln!("{:?}", cause);
                Self::InternalServerError("Internal Server Error".to_string())
            }
        }
    }
}

impl From<LogoutError> for ApiError {
    fn from(err: LogoutError) -> Self {
        match err {
            LogoutError::Unknown(cause) => {
                eprintln!("{:?}", cause);
                Self::InternalServerError("Internal Server Error".to_string())
            }
        }
    }
}

impl From<validator::ValidationError> for ApiError {
    fn from(err: validator::ValidationError) -> Self {
        Self::BadRequest(err.to_string())
    }
}

impl From<validator::ValidationErrors> for ApiError {
    fn from(err: validator::ValidationErrors) -> Self {
        Self::BadRequest(err.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        use ApiError::*;

        match self {
            BadRequest(_) => StatusCode::BAD_REQUEST.into_response(),
            Conflict(_) => StatusCode::CONFLICT.into_response(),
            Gone => StatusCode::GONE.into_response(),
            InternalServerError(e) => {
                eprintln!("{}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            NotFound => StatusCode::NOT_FOUND.into_response(),
            Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            UnprocessableEntity(_) => StatusCode::UNPROCESSABLE_ENTITY.into_response(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user: UserData,
    pub access_token: String,  // New: separate access token
    pub refresh_token: String, // New: refresh token
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub user: UserData,
}

#[derive(Debug, Serialize)]
pub struct UserData {
    pub email: String,
    pub username: String,
    pub bio: String,
    pub image: Option<String>,
    pub email_verified: bool,
}

impl UserData {
    pub fn from_user(user: crate::domain::auth::models::User) -> Self {
        Self {
            email: user.email,
            username: user.username,
            bio: user.bio.unwrap_or_default(), // Empty string if None
            image: user.image,
            email_verified: user.email_verified, // Keep as Option<String>
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ForgotPasswordResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct ResetPasswordResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub message: String,
}
