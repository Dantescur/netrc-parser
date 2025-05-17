//! A modern and idiomatic .netrc parser in Rust

mod error;
pub use error::NetrcError;

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Represents a single machine entry
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NetrcMachine {
    pub machine: String,
    pub login: String,
    pub password: String,
    pub account: Option<String>,
    pub macdef: Option<String>,
}

/// Represents a parsed .netrc file
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Netrc {
    pub machines: Vec<NetrcMachine>,
}

impl Netrc {
    /// Parse from a &str
    pub fn parse_from_str(input: &str) -> Result<Self, NetrcError> {
        let re = Regex::new(
            r"(?m)^\s*machine\s+(\S+)\s+login\s+(\S+)\s+password\s+(\S+)(?:\s+account\s+(\S+))?",
        )
        .unwrap();
        let mut machines = Vec::new();
        for cap in re.captures_iter(input) {
            machines.push(NetrcMachine {
                machine: cap[1].to_string(),
                login: cap[2].to_string(),
                password: cap[3].to_string(),
                account: cap.get(4).map(|m| m.as_str().to_string()),
            });
        }

        Ok(Netrc { machines })
    }

    /// Parse from a file path
    pub fn parse_from_path<P: AsRef<Path>>(path: P) -> Result<Self, NetrcError> {
        let content = fs::read_to_string(path)?;
        Self::parse_from_str(&content)
    }

    /// Get credentials for a specific machine
    pub fn get(&self, machine: &str) -> Option<&NetrcMachine> {
        self.machines.iter().find(|m| m.machine == machine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_entry() {
        let input = "machine example.com login user password pass";
        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("example.com").unwrap();

        assert_eq!(creds.login, "user");
        assert_eq!(creds.password, "pass");
        assert!(creds.account.is_none());
    }

    #[test]
    fn parse_with_account() {
        let input = "machine api.com login alice password secret account dev";
        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("api.com").unwrap();

        assert_eq!(creds.account.as_deref(), Some("dev"));
    }

    #[test]
    fn parse_default_entry() {
        let input = "default login guest password guess123";
        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("default").unwrap();

        assert_eq!(creds.login, "guest");
        assert_eq!(creds.password, "guess123");
    }

    #[test]
    fn parse_macdef_and_account() {
        let input = r#"
        machine internal login root password rootpass account admin
        macdef init
        echo Initializing connection...
        EOF
    "#;

        let netrc = Netrc::parse_from_str(input).unwrap();
        let creds = netrc.get("internal").unwrap();

        assert_eq!(creds.account.as_deref(), Some("admin"));
        assert!(creds.macdef.is_some());
        assert!(
            creds
                .macdef
                .as_ref()
                .unwrap()
                .contains("echo Initializing connection")
        );
    }

    #[cfg(unix)]
    #[test]
    fn warn_insecure_permissions() {
        use std::fs::{self, File};
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        write!(file, "machine test.com login user password pass").unwrap();

        // Set world-readable permissions (insecure)
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o644)).unwrap();

        let result = Netrc::parse_from_path(file.path());
        assert!(matches!(result, Err(NetrcError::InsecurePermissions)));
    }

    #[test]
    fn write_to_file_roundtrip() {
        let mut netrc = Netrc::default();
        netrc.machines.push(NetrcMachine {
            machine: "foo.com".into(),
            login: "john".into(),
            password: "secret".into(),
            account: Some("admin".into()),
            macdef: None,
        });

        let output = netrc.to_string();
        assert!(output.contains("machine foo.com login john password secret account admin"));
    }

    #[test]
    fn serialize_to_json() {
        let netrc = Netrc::parse_from_str("machine foo login user password pass").unwrap();
        let json = serde_json::to_string(&netrc).unwrap();
        assert!(json.contains("foo"));
    }
}
