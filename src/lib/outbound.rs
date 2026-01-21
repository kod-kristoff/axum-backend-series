use sqlx::PgPool;

pub mod email_client;
pub mod sqlx_email_verification_repository;
pub mod sqlx_health_check;
pub mod sqlx_user_repository;

pub async fn create_db(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let db = PgPool::connect(database_url).await?;

    sqlx::migrate!("./migrations").run(&db).await?;
    Ok(db)
}
