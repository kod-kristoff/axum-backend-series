use std::sync::Arc;

use axum::{
    Router,
    extract::FromRef,
    routing::{get, post},
};
use tokio::net;

use crate::{
    domain::{auth::ports::AuthService, health::HealthService},
    inbound::http::handlers::{
        auth::{current_user, forgot_password, login, register, reset_password, verify_email},
        health::health_check,
    },
};

mod handlers;
mod middleware;
mod responses;

#[derive(Clone, FromRef)]
pub struct AppState {
    auth_service: Arc<dyn AuthService>,
    health_service: Arc<dyn HealthService>,
}

pub struct HttpServer {
    router: axum::Router,
    listener: net::TcpListener,
}

impl HttpServer {
    pub async fn new(
        auth_service: Arc<dyn AuthService>,
        health_service: Arc<dyn HealthService>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let state = AppState {
            auth_service,
            health_service,
        };

        let router = axum::Router::new()
            .nest("/api", api_routes())
            .route("/health", get(health_check))
            .with_state(state);

        let listener = net::TcpListener::bind("0.0.0.0:3000").await?;
        Ok(Self { router, listener })
    }

    pub async fn run(self) -> Result<(), anyhow::Error> {
        println!(
            "Server is running on {}",
            self.listener.local_addr().unwrap()
        );
        println!("Available endpoints:");
        println!("  POST /api/users                 - Register new user");
        println!("  POST /api/users/login           - Login existing user");
        println!("  GET  /api/user                  - Get current user (requires auth)");
        println!("  GET  /api/auth/verify-email     - Verify email");
        println!("  POST /api/auth/forgot-password  - Forgot password");
        println!("  POST /api/auth/reset-password   - Reset password");
        println!("  GET  /health                    - Health check");

        axum::serve(self.listener, self.router).await?;
        Ok(())
    }
}

fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/users", post(register))
        .route("/users/login", post(login))
        .route("/user", get(current_user))
        .route("/auth/verify-email", get(verify_email))
        .route("/auth/forgot-password", post(forgot_password))
        .route("/auth/reset-password", post(reset_password))
}
