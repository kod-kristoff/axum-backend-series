use std::sync::Arc;

use axum::{
    Router,
    extract::FromRef,
    routing::{get, post},
};
use sqlx::PgPool;
use tokio::net;

use crate::{
    domain::{auth::ports::AuthService, health::HealthService},
    inbound::http::handlers::{
        auth::{current_user, login, register, verify_email},
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

// impl AppState {
//     pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {

//         let user_repository = Arc::new(SqlxUserRepository::new(db.clone()));

//         let email_verification_repository =
//             Arc::new(SqlxEmailVerificationRepository::new(db.clone()));

//         let email_service =
//             Arc::new(EmailService::new().expect("Failed to initialize email service"));
//         Ok(Self {
//             db,
//             user_repository,
//             email_verification_repository,
//             email_service,
//         })
//     }
// }

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
        println!("  POST /api/users         - Register new user");
        println!("  POST /api/users/login   - Login existing user");
        println!("  GET  /api/user          - Get current user (requires auth)");
        println!("  GET  /health            - Health check");

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
}
