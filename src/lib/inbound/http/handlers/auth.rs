use axum::{Json, extract::State};
use validator::Validate;

use crate::{
    domain::auth::models::{
        password_reset_tokens::{ForgotPasswordRequest, ResetPasswordRequest},
        user::{LoginUserRequest, RegisterUserRequest, VerifyEmailRequest},
    },
    inbound::http::{
        AppState,
        middleware::RequireAuth,
        responses::{
            ApiError, ForgotPasswordResponse, ResetPasswordResponse, UserData, UserResponse,
        },
    },
};

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    // Validate input data
    payload.user.validate().map_err(ApiError::from)?;

    let (user, token) = state
        .auth_service
        .register_user(&payload)
        .await
        .map_err(ApiError::from)?;
    // Build response
    let user_data = UserData::from_user_with_token(user, token);
    let response = UserResponse { user: user_data };

    Ok(Json(response))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    // Validate input
    payload.user.validate().map_err(ApiError::from)?;

    let (user, token) = state
        .auth_service
        .login(&payload)
        .await
        .map_err(ApiError::from)?;
    // Build response
    let user_data = UserData::from_user_with_token(user, token);
    let response = UserResponse { user: user_data };

    Ok(Json(response))
}

pub async fn current_user(
    RequireAuth(user): RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<UserResponse>, ApiError> {
    let token = state
        .auth_service
        .generate_token_for_user(&user.id)
        .await
        .map_err(ApiError::from)?;
    // Build response
    let user_data = UserData::from_user_with_token(user, token);
    let response = UserResponse { user: user_data };

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
