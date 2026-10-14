use greater_spire::{Config, IdentityRuntime};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: runtime_smoke <identity.toml> [peer]")?;
    let mut runtime = IdentityRuntime::start(Config::from_file(path)?).await?;
    println!("{:#?}", runtime.status().await);
    #[cfg(feature = "http")]
    if let Some(peer) = std::env::args().nth(2) {
        let response = runtime.http_client(&peer)?.get("/").await?;
        println!("{}: {}", peer, response.status());
    }
    runtime.shutdown().await;
    Ok(())
}
