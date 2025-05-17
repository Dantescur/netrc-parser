use netrc_parser::{Netrc, NetrcError};

fn main() -> Result<(), NetrcError> {
    let path = dirs::home_dir()
        .ok_or_else(|| NetrcError::FileNotFound("Home directory not found".to_string()))?
        .join(".netrc");
    let netrc = Netrc::parse_from_path(&path)?;
    if let Some(creds) = netrc.get("surge.surge.sh") {
        println!("Login: {}, Password: {}", creds.login, creds.password);
    } else {
        println!("No credentials found for surge.surge.sh");
    }
    Ok(())
}
