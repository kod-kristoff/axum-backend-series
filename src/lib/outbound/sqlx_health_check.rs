use async_trait::async_trait;
use sqlx::PgPool;

use crate::domain::health::HealthService;

pub struct SqlxHealthCheck {
    db: PgPool,
}

impl SqlxHealthCheck {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl HealthService for SqlxHealthCheck {
    async fn health_check(&self) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query("SELECT 1").execute(&self.db).await?;
        Ok(())
    }
}
