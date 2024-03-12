use serde::{Deserialize, Serialize};

/// This app connects to different cloud services (DB, Auth, etc.)
/// Try to centrally manage all of the related secrets here
///  Store this in TOML in one place and DO NOT CHECK IN THE SECRETS FILE!
///
/// We could in theory encrypt this file, but then we'd need to store
/// the encryption key in plaintext so it would default the purpose
///
/// Solve this more securely when we actually have real customers
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecretsError {
    #[error("File access problem {0}")]
    File(#[from] std::io::Error),
    #[error("TOML parsing problem {0}")]
    TomlParsing(#[from] toml::de::Error),
}

/// A list of the Secrets needed to run the webserver
/// Everything is listed as Option<> so we can do forwards and backwards compat
/// All functions must check if the desired secret is defined and do something function
/// specific if it's not
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Secrets {
    /// Username for the timescale_db account with WRITE permissions
    pub timescale_db_write_user: Option<String>,
    /// Secret for the timescale_db account with WRITE permissions
    pub timescale_db_write_secret: Option<String>,
    /// Username for the timescale_db account with READ permissions
    pub timescale_db_read_user: Option<String>,
    /// Secret for the timescale_db account with READ permissions
    pub timescale_db_read_secret: Option<String>,
    /// Secret for Clerk.com auth service for the dev deployment
    pub clerk_auth_dev_secret: Option<String>,
    /// Secret for Clerk.com auth service for the production deployment
    pub clerk_auth_prod_secret: Option<String>,
}

impl Secrets {
    /// Parse the Secrets struct from the given file or return an error
    pub fn from_toml_file(filename: &String) -> Result<Secrets, SecretsError> {
        let contents = std::fs::read_to_string(filename)?;
        Ok(toml::from_str(&contents)?)
    }
}

#[cfg(test)]
mod test {
    use common::test_utils::test_dir;

    use super::Secrets;

    #[test]
    fn load_toml() {
        let secrets =
            Secrets::from_toml_file(&test_dir("webserver", "tests/test-secrets.toml")).unwrap();
        assert_eq!(secrets.timescale_db_write_user, Some("alice".to_string()));
        assert_eq!(secrets.clerk_auth_dev_secret, None);
    }
}
