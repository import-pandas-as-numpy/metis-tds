use std::net::SocketAddr;

use uuid::Uuid;

use crate::{personality::Personality, tds::login7::LoginRequest};

#[derive(Clone)]
pub struct SessionState {
    pub connection_id: Uuid,
    pub session_id: u32,
    pub source_addr: SocketAddr,
    pub login_name: String,
    pub effective_login: String,
    pub client_hostname: Option<String>,
    pub application_name: Option<String>,
    pub current_database: String,
    pub language: String,
    pub xp_cmdshell_enabled: bool,
    pub clr_enabled: bool,
    pub ole_automation_enabled: bool,
    pub ad_hoc_distributed_queries_enabled: bool,
    pub impersonation_stack: Vec<String>,
    pub transaction_depth: u32,
    pub request_count: u64,
    pub synthetic_logins: Vec<String>,
    pub synthetic_jobs: Vec<String>,
    pub synthetic_assemblies: Vec<String>,
}

impl SessionState {
    pub fn new(
        connection_id: Uuid,
        session_id: u32,
        source_addr: SocketAddr,
        login: &LoginRequest,
        personality: &Personality,
    ) -> Self {
        let database = if login.database.is_empty() {
            personality.default_database.clone()
        } else {
            login.database.clone()
        };
        Self {
            connection_id,
            session_id,
            source_addr,
            login_name: login.username.clone(),
            effective_login: login.username.clone(),
            client_hostname: optional(&login.client_hostname),
            application_name: optional(&login.application_name),
            current_database: database,
            language: if login.language.is_empty() {
                personality.language.clone()
            } else {
                login.language.clone()
            },
            xp_cmdshell_enabled: false,
            clr_enabled: false,
            ole_automation_enabled: false,
            ad_hoc_distributed_queries_enabled: false,
            impersonation_stack: Vec::new(),
            transaction_depth: 0,
            request_count: 0,
            synthetic_logins: Vec::new(),
            synthetic_jobs: Vec::new(),
            synthetic_assemblies: Vec::new(),
        }
    }
}

fn optional(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}
