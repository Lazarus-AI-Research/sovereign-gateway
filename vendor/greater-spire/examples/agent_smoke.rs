use greater_spire::{AgentConfig, EmbeddedAgent, SPIRE_SERVER_VERSION};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: cargo run --example agent_smoke -- <agent.toml>")?;
    eprintln!("expecting stock SPIRE Server v{SPIRE_SERVER_VERSION}");
    let config = AgentConfig::from_toml_file(path)?;
    let agent = EmbeddedAgent::start(config).await?;
    println!("{:#?}", agent.status().await);
    agent.shutdown().await;
    Ok(())
}
