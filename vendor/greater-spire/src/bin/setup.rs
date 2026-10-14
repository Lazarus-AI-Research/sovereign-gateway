//! Small provisioning utility intended for installers and scheduled renewal.
use greater_spire::{static_ca::StaticCa, SpiffeId, TrustDomain};
use std::path::Path;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, domain, directory, days] if command == "init-ca" => {
            let domain: TrustDomain = domain.as_str().try_into()?;
            if Path::new(directory).exists() {
                let ca = StaticCa::load(directory)?;
                if ca.trust_domain() != &domain { return Err("existing CA has a different trust domain".into()); }
                println!("Using existing CA for {} (expires {})", ca.trust_domain(), ca.expires_at_unix());
            } else {
                let ca = StaticCa::generate(domain, lifetime(days)?)?;
                ca.write_new(directory)?;
                println!("Created CA in {directory}");
            }
        }
        [command, ca_directory, id, directory, days] if command == "issue" => {
            let ca = StaticCa::load(ca_directory)?;
            let id: SpiffeId = id.as_str().try_into()?;
            let issued = ca.issue_svid(&id, lifetime(days)?)?;
            #[cfg(unix)] let path = issued.publish(directory)?;
            #[cfg(not(unix))] let path = {
                issued.write_generation(directory)?;
                std::path::PathBuf::from(directory)
            };
            println!("Issued {id} through {} (expires {})", path.display(), issued.expires_at_unix);
        }
        _ => return Err("usage:\n  greater-spire-setup init-ca <trust-domain> <new-ca-directory> <days>\n  greater-spire-setup issue <ca-directory> <spiffe-id> <workload-directory> <days>\n\nOn Unix, issue atomically replaces workload-directory/current and retains old generations.\nRun issue from a scheduled renewal job; init-ca preserves an existing CA.".into()),
    }
    Ok(())
}

fn lifetime(days: &str) -> Result<Duration, Box<dyn std::error::Error>> {
    let seconds = days
        .parse::<u64>()?
        .checked_mul(86400)
        .ok_or("lifetime overflow")?;
    if seconds == 0 {
        return Err("days must be positive".into());
    }
    Ok(Duration::from_secs(seconds))
}
