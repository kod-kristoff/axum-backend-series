use std::env;
use std::sync::Arc;

use axum_backend_series::domain::auth::service::Service;
use axum_backend_series::inbound::http::HttpServer;
use axum_backend_series::outbound::create_db;
use axum_backend_series::outbound::email_client::EmailService;
use axum_backend_series::outbound::sqlx_email_verification_repository::SqlxEmailVerificationRepository;
use axum_backend_series::outbound::sqlx_health_check::SqlxHealthCheck;
use axum_backend_series::outbound::sqlx_user_repository::SqlxUserRepository;

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let database_url =
        env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env file or environment");

    let db = create_db(&database_url)
        .await
        .expect("Failed to connect to database");

    println!("Connected to database successfully!");

    let user_repository = Arc::new(SqlxUserRepository::new(db.clone()));

    let email_verification_repository = Arc::new(SqlxEmailVerificationRepository::new(db.clone()));

    let user_notifier = Arc::new(EmailService::new().expect("Failed to initialize email service"));

    let auth_service = Arc::new(Service::new(
        user_repository,
        email_verification_repository,
        user_notifier,
    ));

    let health_service = Arc::new(SqlxHealthCheck::new(db.clone()));

    let http_server = HttpServer::new(auth_service, health_service)
        .await
        .expect("Failed to create server");

    http_server.run().await.expect("Failed to run");
}
