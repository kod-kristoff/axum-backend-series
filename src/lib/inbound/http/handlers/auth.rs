use axum::{Json, extract::State};
use validator::Validate;

use crate::{
    domain::auth::models::{
        password_reset_tokens::{ForgotPasswordRequest, ResetPasswordRequest},
        refresh_token::{LogoutRequest, RefreshTokenRequest},
        user::{LoginUserRequest, RegisterUserRequest, VerifyEmailRequest},
    },
    inbound::http::{
        AppState,
        middleware::RequireAuth,
        responses::{
            ApiError, ForgotPasswordResponse, LoginResponse, LogoutResponse, RefreshTokenResponse,
            ResetPasswordResponse, UserData, UserResponse,
        },
    },
};

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Validate input data
    payload.user.validate().map_err(ApiError::from)?;

    let (user, access_token, refresh_token) = state
        .auth_service
        .register_user(&payload)
        .await
        .map_err(ApiError::from)?;
    // Build response
    let response = LoginResponse {
        user: UserData::from_user(user),
        access_token,
        refresh_token,
    };

    Ok(Json(response))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginUserRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Validate input
    payload.user.validate().map_err(ApiError::from)?;

    let (user, access_token, refresh_token) = state
        .auth_service
        .login(&payload)
        .await
        .map_err(ApiError::from)?;
    // Build response
    let response = LoginResponse {
        user: UserData::from_user(user),
        access_token,
        refresh_token,
    };

    Ok(Json(response))
}

pub async fn current_user(RequireAuth(user): RequireAuth) -> Result<Json<UserResponse>, ApiError> {
    // Build response
    let response = UserResponse {
        user: UserData::from_user(user),
    };

    Ok(Json(response))
}

pub async fn verify_email(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Extract token from query params
    let token = params
        .get("token")
        .ok_or(ApiError::BadRequest("'token' is missing".to_string()))?;

    state
        .auth_service
        .verify_email(&VerifyEmailRequest { token })
        .await
        .map_err(ApiError::from)?;

    Ok(Json(serde_json::json!({
        "message": "Email verified successfully!"
    })))
}

// Handler for "Forgot Password" - generates and emails reset token
pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, ApiError> {
    // Validate email format
    payload.validate().map_err(ApiError::from)?;

    state
        .auth_service
        .forgot_password(&payload)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(ForgotPasswordResponse {
        message: "If that email exists, a password reset link has been sent.".to_string(),
    }))
}
// Handler for actually resetting the password
pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, ApiError> {
    // Validate new password
    payload.validate()?;

    state
        .auth_service
        .reset_password(&payload)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(ResetPasswordResponse {
        message: "Password has been reset successfully. You can now login with your new password."
            .to_string(),
    }))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<RefreshTokenResponse>, ApiError> {
    let (access_token, refresh_token) = state
        .auth_service
        .refresh_token(&payload)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(RefreshTokenResponse {
        access_token,
        refresh_token,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<Json<LogoutResponse>, ApiError> {
    // Simply delete the refresh token from database
    state
        .auth_service
        .logout(&payload)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(LogoutResponse {
        message: "Logged out successfully".to_string(),
    }))
}
