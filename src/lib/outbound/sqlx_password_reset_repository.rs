use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::auth::models::password_reset_tokens::PasswordResetToken;
use crate::domain::auth::ports::PasswordResetRepository;

#[derive(Clone)]
pub struct SqlxPasswordResetRepository {
    db: PgPool,
}

impl SqlxPasswordResetRepository {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl PasswordResetRepository for SqlxPasswordResetRepository {
    async fn create_token(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<PasswordResetToken, sqlx::Error> {
        let reset_token = sqlx::query_as::<_, PasswordResetToken>(
            r#"
            INSERT INTO password_reset_tokens (user_id, token, expires_at)
            VALUES ($1, $2, $3)
            RETURNING id, user_id, token, expires_at, created_at
            "#,
        )
        .bind(user_id)
        .bind(token)
        .bind(expires_at)
        .fetch_one(&self.db)
        .await?;

        Ok(reset_token)
    }

    async fn find_by_token(&self, token: &str) -> Result<Option<PasswordResetToken>, sqlx::Error> {
        let reset_token = sqlx::query_as::<_, PasswordResetToken>(
            r#"
            SELECT id, user_id, token, expires_at, created_at
            FROM password_reset_tokens
            WHERE token = $1
            "#,
        )
        .bind(token)
        .fetch_optional(&self.db)
        .await?;

        Ok(reset_token)
    }

    async fn delete_token(&self, token: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM password_reset_tokens
            WHERE token = $1
            "#,
        )
        .bind(token)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn delete_all_user_tokens(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM password_reset_tokens
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }
}
