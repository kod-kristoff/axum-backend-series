use async_trait::async_trait;

#[async_trait]
pub trait HealthService: Send + Sync {
    async fn health_check(&self) -> Result<(), Box<dyn std::error::Error>>;
}
