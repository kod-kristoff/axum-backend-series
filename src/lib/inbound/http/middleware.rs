use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderMap, request::Parts},
};

use crate::{
    domain::auth::models::{User, user::LoginError},
    inbound::http::{AppState, responses::ApiError},
};

// For protected routes - requires valid JWT
pub struct RequireAuth(pub User);

// For optional auth - extracts user if token present
pub struct OptionalAuth(pub Option<User>);

impl<S> FromRequestParts<S> for RequireAuth
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Extract Authorization header
        let headers = &parts.headers;
        let token = extract_token_from_headers(headers).ok_or(ApiError::Unauthorized)?;

        let user = app_state
            .auth_service
            .get_user_from_token(&token)
            .await
            .map_err(ApiError::from)?
            .ok_or(ApiError::Unauthorized)?;

        Ok(RequireAuth(user))
    }
}

impl<S> FromRequestParts<S> for OptionalAuth
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Try to extract Authorization header
        let headers = &parts.headers;
        let token = match extract_token_from_headers(headers) {
            Some(token) => token,
            None => return Ok(OptionalAuth(None)),
        };

        match app_state.auth_service.get_user_from_token(&token).await {
            Ok(user) => Ok(OptionalAuth(user)),
            Err(LoginError::Unauthorized) => Ok(OptionalAuth(None)),
            Err(err) => Err(ApiError::from(err)),
        }
    }
}

fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get("Authorization")?.to_str().ok()?;

    auth_header
        .strip_prefix("Token ")
        .map(|token| token.to_string())
}
