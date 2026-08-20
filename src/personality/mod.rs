use serde::Deserialize;

use crate::tds::login7::LoginRequest;

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Personality {
    pub server_name: String,
    pub instance_name: String,
    pub sql_version: String,
    pub product_version: String,
    pub product_level: String,
    pub edition: String,
    pub os_version: String,
    pub domain: String,
    pub default_database: String,
    pub language: String,
    pub accept_unknown_logins: bool,
    pub unknown_query_behavior: UnknownQueryBehavior,
    pub databases: Vec<String>,
    pub logins: Vec<LoginDefinition>,
    pub linked_servers: Vec<String>,
    pub honey_objects: Vec<String>,
}

impl Default for Personality {
    fn default() -> Self {
        Self {
            server_name: "SQL-FIN-01".into(),
            instance_name: "MSSQLSERVER".into(),
            sql_version: "Microsoft SQL Server 2022 (RTM-CU18) - 16.0.4185.3 (X64)".into(),
            product_version: "16.0.4185.3".into(),
            product_level: "RTM".into(),
            edition: "Enterprise Edition (64-bit)".into(),
            os_version: "Windows Server 2022 Datacenter 10.0 (Build 20348)".into(),
            domain: "CORP".into(),
            default_database: "master".into(),
            language: "us_english".into(),
            accept_unknown_logins: true,
            unknown_query_behavior: UnknownQueryBehavior::Empty,
            databases: vec![
                "master".into(),
                "tempdb".into(),
                "model".into(),
                "msdb".into(),
            ],
            logins: Vec::new(),
            linked_servers: Vec::new(),
            honey_objects: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownQueryBehavior {
    Empty,
    Success,
    SyntaxError,
    PermissionDenied,
}

pub struct LoginDefinition {
    pub name: String,
    password: Option<String>,
    pub locked: bool,
    pub honey: bool,
}

impl<'de> Deserialize<'de> for LoginDefinition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            name: String,
            password: Option<String>,
            #[serde(default)]
            locked: bool,
            #[serde(default)]
            honey: bool,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            name: raw.name,
            password: raw.password,
            locked: raw.locked,
            honey: raw.honey,
        })
    }
}

impl Clone for LoginDefinition {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            password: self.password.clone(),
            locked: self.locked,
            honey: self.honey,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthDecision {
    Accept,
    Reject,
    Locked,
}

impl Personality {
    pub fn authenticate(&self, login: &LoginRequest) -> AuthDecision {
        if let Some(decoy) = self
            .logins
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(&login.username))
        {
            if decoy.locked {
                return AuthDecision::Locked;
            }
            return match &decoy.password {
                Some(expected) if login.password.as_deref() != Some(expected.as_str()) => {
                    AuthDecision::Reject
                }
                _ => AuthDecision::Accept,
            };
        }
        if self.accept_unknown_logins {
            AuthDecision::Accept
        } else {
            AuthDecision::Reject
        }
    }

    pub fn is_honey_login(&self, name: &str) -> bool {
        self.logins
            .iter()
            .any(|entry| entry.honey && entry.name.eq_ignore_ascii_case(name))
    }
}
