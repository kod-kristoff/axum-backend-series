use std::sync::Arc;

use axum::extract::FromRef;
use sqlx::PgPool;

use crate::{
    repositories::{
        email_verification_repository::SqlxEmailVerificationRepository,
        password_reset_repository::SqlxPasswordResetRepository,
        traits::{EmailVerificationRepository, PasswordResetRepository, UserRepository},
        user_repository::SqlxUserRepository,
    },
    services::email_service::EmailService,
};

#[derive(Clone, FromRef)]
pub struct AppState {
    pub db: PgPool,
    pub user_repository: Arc<dyn UserRepository>,
    pub email_verification_repository: Arc<dyn EmailVerificationRepository>,
    pub password_reset_repository: Arc<dyn PasswordResetRepository>,
    pub email_service: Arc<EmailService>,
}

impl AppState {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let db = PgPool::connect(database_url).await?;

        sqlx::migrate!("./migrations").run(&db).await?;

        let user_repository = Arc::new(SqlxUserRepository::new(db.clone()));

        let email_verification_repository =
            Arc::new(SqlxEmailVerificationRepository::new(db.clone()));

        let password_reset_repository = Arc::new(SqlxPasswordResetRepository::new(db.clone()));
        let email_service =
            Arc::new(EmailService::new().expect("Failed to initialize email service"));
        Ok(Self {
            db,
            user_repository,
            email_verification_repository,
            password_reset_repository,
            email_service,
        })
    }
}
