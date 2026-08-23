use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;

use crate::{
    personality::{Personality, UnknownQueryBehavior},
    session::SessionState,
    tds::{
        rpc::RpcRequest,
        tokens::{ResultSet, SqlError},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    EnvironmentDiscovery,
    DatabaseEnumeration,
    PrincipalEnumeration,
    PermissionEnumeration,
    Configuration,
    XpCmdshell,
    ExternalScripts,
    OleAutomation,
    ExecuteAs,
    LoginManipulation,
    RoleManipulation,
    ClrActivity,
    LinkedServerActivity,
    FilesystemActivity,
    SqlAgentActivity,
    HoneyObjectAccess,
    DatabaseContext,
    Transaction,
    Unknown,
}

impl Classification {
    pub fn risk_tags(self) -> &'static [&'static str] {
        match self {
            Self::XpCmdshell => &["os_command_execution"],
            Self::ExternalScripts => &["external_script_execution"],
            Self::OleAutomation => &["ole_automation"],
            Self::ExecuteAs => &["impersonation"],
            Self::LoginManipulation | Self::RoleManipulation => &["privilege_manipulation"],
            Self::ClrActivity => &["clr_payload"],
            Self::LinkedServerActivity => &["lateral_movement"],
            Self::FilesystemActivity => &["filesystem_access"],
            Self::SqlAgentActivity => &["persistence", "os_command_execution"],
            Self::HoneyObjectAccess => &["honey_object"],
            _ => &[],
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StateChange {
    pub property: String,
    pub old_value: String,
    pub new_value: String,
}

#[derive(Debug)]
pub struct Outcome {
    pub classification: Classification,
    pub risk_tags: Vec<String>,
    pub result_sets: Vec<ResultSet>,
    pub messages: Vec<String>,
    pub error: Option<SqlError>,
    pub state_changes: Vec<StateChange>,
    pub payload_candidate: Option<PayloadCandidate>,
    pub honey_object: Option<String>,
}

#[derive(Debug)]
pub struct PayloadCandidate {
    pub kind: String,
    pub bytes: Vec<u8>,
}

impl Outcome {
    fn empty(classification: Classification) -> Self {
        Self {
            classification,
            risk_tags: classification
                .risk_tags()
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            result_sets: Vec::new(),
            messages: Vec::new(),
            error: None,
            state_changes: Vec::new(),
            payload_candidate: None,
            honey_object: None,
        }
    }
}

pub fn handle_rpc(
    session: &mut SessionState,
    personality: &Personality,
    rpc: &RpcRequest,
) -> Outcome {
    let statements = rpc
        .batches
        .iter()
        .filter(|batch| !batch.no_execute)
        .map(|batch| {
            if batch.procedure.eq_ignore_ascii_case("sp_executesql") {
                if let Some(sql) = batch.parameters.first().and_then(|p| p.value.as_text()) {
                    let mut expanded = sql.to_owned();
                    for parameter in batch.parameters.iter().skip(2) {
                        if !parameter.name.is_empty() {
                            expanded = expanded
                                .replace(&parameter.name, &parameter.value.to_sql_literal());
                        }
                    }
                    return expanded;
                }
            }
            let arguments = batch
                .parameters
                .iter()
                .map(|p| p.value.to_sql_literal())
                .collect::<Vec<_>>()
                .join(", ");
            if arguments.is_empty() {
                format!("EXEC {}", batch.procedure)
            } else {
                format!("EXEC {} {arguments}", batch.procedure)
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    handle_sql(session, personality, &statements)
}

pub fn handle_sql(session: &mut SessionState, personality: &Personality, sql: &str) -> Outcome {
    let normalized = normalize(sql);
    let mut outcome = Outcome::empty(classify(&normalized, personality));
    if let Some(object) = personality
        .honey_objects
        .iter()
        .find(|name| normalized.contains(&name.to_uppercase()))
    {
        outcome.classification = Classification::HoneyObjectAccess;
        outcome.risk_tags = vec!["honey_object".into()];
        outcome.honey_object = Some(object.clone());
    }

    for statement in split_statements(sql) {
        apply_statement(session, personality, statement, &mut outcome);
        if outcome.error.is_some() {
            break;
        }
    }
    outcome
}

pub fn normalize(sql: &str) -> String {
    static BLOCK: OnceLock<Regex> = OnceLock::new();
    static LINE: OnceLock<Regex> = OnceLock::new();
    static SPACE: OnceLock<Regex> = OnceLock::new();
    let no_block = BLOCK
        .get_or_init(|| Regex::new(r"(?s)/\*.*?\*/").expect("constant regex"))
        .replace_all(sql, " ");
    let no_line = LINE
        .get_or_init(|| Regex::new(r"(?m)--[^\r\n]*").expect("constant regex"))
        .replace_all(&no_block, " ");
    SPACE
        .get_or_init(|| Regex::new(r"\s+").expect("constant regex"))
        .replace_all(no_line.trim(), " ")
        .to_uppercase()
}

pub fn classify(normalized: &str, personality: &Personality) -> Classification {
    if personality
        .honey_objects
        .iter()
        .any(|o| normalized.contains(&o.to_uppercase()))
    {
        return Classification::HoneyObjectAccess;
    }
    if normalized.contains("XP_CMDSHELL") {
        return Classification::XpCmdshell;
    }
    if normalized.contains("SP_OA") || normalized.contains("OLE AUTOMATION") {
        return Classification::OleAutomation;
    }
    if normalized.contains("SP_EXECUTE_EXTERNAL_SCRIPT") || normalized.contains("EXTERNAL SCRIPT") {
        return Classification::ExternalScripts;
    }
    if normalized.contains("ASSEMBLY") || normalized.contains("CLR ENABLED") {
        return Classification::ClrActivity;
    }
    if normalized.contains("LINKED_SERVER")
        || normalized.contains("SP_LINKEDSERVERS")
        || normalized.contains("SYS.SERVERS")
        || normalized.contains("OPENQUERY")
        || normalized.contains("EXEC (") && normalized.contains(" AT ")
    {
        return Classification::LinkedServerActivity;
    }
    if normalized.contains("MSDB.DBO.SP_") && normalized.contains("JOB")
        || normalized.contains("SYSJOBS")
    {
        return Classification::SqlAgentActivity;
    }
    if normalized.contains("BACKUP ")
        || normalized.contains("RESTORE ")
        || normalized.contains("BULK INSERT")
        || normalized.contains("OPENROWSET")
        || normalized.contains("XP_FILEEXIST")
    {
        return Classification::FilesystemActivity;
    }
    if normalized.contains("EXECUTE AS") || normalized.starts_with("REVERT") {
        return Classification::ExecuteAs;
    }
    if normalized.contains("CREATE LOGIN")
        || normalized.contains("ALTER LOGIN")
        || normalized.contains("DROP LOGIN")
    {
        return Classification::LoginManipulation;
    }
    if normalized.contains("SP_ADDROLEMEMBER")
        || normalized.contains("SERVER ROLE")
        || normalized.contains(" GRANT ")
        || normalized.starts_with("GRANT ")
        || normalized.contains(" DENY ")
        || normalized.contains(" REVOKE ")
    {
        return Classification::RoleManipulation;
    }
    if normalized.contains("SP_CONFIGURE") || normalized == "RECONFIGURE" {
        return Classification::Configuration;
    }
    if normalized.contains("SYS.DATABASES") || normalized.contains("SP_DATABASES") {
        return Classification::DatabaseEnumeration;
    }
    if normalized.contains("SYS.SERVER_PRINCIPALS")
        || normalized.contains("SYS.SQL_LOGINS")
        || normalized.contains("SP_HELPSRVLOGIN")
    {
        return Classification::PrincipalEnumeration;
    }
    if normalized.contains("FN_MY_PERMISSIONS")
        || normalized.contains("HAS_PERMS_BY_NAME")
        || normalized.contains("ROLEMEMBER")
    {
        return Classification::PermissionEnumeration;
    }
    if normalized.starts_with("USE ") {
        return Classification::DatabaseContext;
    }
    if normalized.starts_with("BEGIN TRAN")
        || normalized.starts_with("COMMIT")
        || normalized.starts_with("ROLLBACK")
    {
        return Classification::Transaction;
    }
    if [
        "@@VERSION",
        "@@SERVERNAME",
        "SERVERPROPERTY",
        "SYSTEM_USER",
        "SUSER_SNAME",
        "USER_NAME",
        "DB_NAME",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
    {
        return Classification::EnvironmentDiscovery;
    }
    Classification::Unknown
}

fn apply_statement(
    session: &mut SessionState,
    personality: &Personality,
    statement: &str,
    outcome: &mut Outcome,
) {
    let normalized = normalize(statement);
    if normalized.is_empty() {
        return;
    }

    if let Some(database) = word_after(statement, "USE") {
        let database = trim_identifier(&database);
        if personality
            .databases
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&database))
        {
            change(
                outcome,
                "current_database",
                &session.current_database,
                &database,
            );
            session.current_database = database;
        } else {
            outcome.error = Some(SqlError {
                number: 911,
                state: 1,
                class: 16,
                message: format!(
                    "Database '{database}' does not exist. Make sure that the name is entered correctly."
                ),
            });
        }
        return;
    }
    if normalized.contains("SP_CONFIGURE") {
        configure(session, statement, &normalized, outcome);
        return;
    }
    if normalized == "RECONFIGURE" || normalized.starts_with("RECONFIGURE ") {
        return;
    }
    if normalized.contains("XP_CMDSHELL") {
        xp_cmdshell(session, statement, personality, outcome);
        return;
    }
    if normalized.contains("EXECUTE AS") {
        let identity = quoted_after(statement, "LOGIN")
            .or_else(|| quoted_after(statement, "USER"))
            .unwrap_or_else(|| "dbo".into());
        session
            .impersonation_stack
            .push(session.effective_login.clone());
        change(
            outcome,
            "effective_login",
            &session.effective_login,
            &identity,
        );
        session.effective_login = identity;
        return;
    }
    if normalized.starts_with("REVERT") {
        if let Some(previous) = session.impersonation_stack.pop() {
            change(
                outcome,
                "effective_login",
                &session.effective_login,
                &previous,
            );
            session.effective_login = previous;
        }
        return;
    }
    if normalized.starts_with("BEGIN TRAN") {
        let old = session.transaction_depth;
        session.transaction_depth = old.saturating_add(1);
        change(
            outcome,
            "transaction_depth",
            &old.to_string(),
            &session.transaction_depth.to_string(),
        );
        return;
    }
    if normalized.starts_with("COMMIT") || normalized.starts_with("ROLLBACK") {
        let old = session.transaction_depth;
        session.transaction_depth = if normalized.starts_with("ROLLBACK") {
            0
        } else {
            old.saturating_sub(1)
        };
        change(
            outcome,
            "transaction_depth",
            &old.to_string(),
            &session.transaction_depth.to_string(),
        );
        return;
    }
    if normalized.contains("CREATE LOGIN") {
        if let Some(name) = word_after(statement, "CREATE LOGIN") {
            let name = trim_identifier(&name);
            session.synthetic_logins.push(name.clone());
            change(outcome, "synthetic_login", "absent", &name);
        }
        return;
    }
    if normalized.contains("CREATE ASSEMBLY") {
        if let Some(name) = word_after(statement, "CREATE ASSEMBLY") {
            let name = trim_identifier(&name);
            session.synthetic_assemblies.push(name.clone());
            change(outcome, "synthetic_assembly", "absent", &name);
        }
        if let Some(bytes) = extract_hex_literal(statement) {
            outcome.payload_candidate = Some(PayloadCandidate {
                kind: "clr_assembly".into(),
                bytes,
            });
        }
        return;
    }
    if normalized.contains("SP_ADD_JOB") {
        let name = quoted_after(statement, "@JOB_NAME")
            .unwrap_or_else(|| format!("Job{}", session.synthetic_jobs.len() + 1));
        session.synthetic_jobs.push(name.clone());
        change(outcome, "synthetic_job", "absent", &name);
        return;
    }
    if normalized.contains("SP_START_JOB") {
        let name = quoted_after(statement, "@JOB_NAME").unwrap_or_else(|| "MaintenancePlan".into());
        outcome
            .messages
            .push(format!("Job '{name}' started successfully."));
        return;
    }
    if normalized.contains("SP_OACREATE") {
        outcome.result_sets.push(ResultSet::single("", "0"));
        return;
    }
    if normalized.contains("XP_FILEEXIST") {
        outcome.result_sets.push(ResultSet {
            columns: vec![
                "File Exists".into(),
                "File is a Directory".into(),
                "Parent Directory Exists".into(),
            ],
            rows: vec![vec![Some("0".into()), Some("0".into()), Some("1".into())]],
        });
        return;
    }
    if normalized.starts_with("BACKUP ") || normalized.starts_with("RESTORE ") {
        outcome.messages.push(
            "Processed 1024 pages for database; synthetic operation completed successfully.".into(),
        );
        return;
    }
    if discovery(session, personality, &normalized, outcome) {
        return;
    }
    unknown(personality.unknown_query_behavior, outcome);
}

fn discovery(
    session: &SessionState,
    personality: &Personality,
    normalized: &str,
    outcome: &mut Outcome,
) -> bool {
    if normalized.contains("@@VERSION") {
        outcome
            .result_sets
            .push(ResultSet::single("", &personality.sql_version));
        return true;
    }
    if normalized.contains("@@SERVERNAME") {
        outcome
            .result_sets
            .push(ResultSet::single("", &personality.server_name));
        return true;
    }
    if normalized.contains("SERVERPROPERTY") {
        let value = if normalized.contains("PRODUCTVERSION") {
            &personality.product_version
        } else if normalized.contains("PRODUCTLEVEL") {
            &personality.product_level
        } else if normalized.contains("EDITION") {
            &personality.edition
        } else if normalized.contains("MACHINENAME") || normalized.contains("SERVERNAME") {
            &personality.server_name
        } else if normalized.contains("INSTANCENAME") {
            &personality.instance_name
        } else {
            &personality.product_version
        };
        outcome.result_sets.push(ResultSet::single("", value));
        return true;
    }
    if normalized.contains("SYSTEM_USER") || normalized.contains("SUSER_SNAME") {
        outcome
            .result_sets
            .push(ResultSet::single("", &session.effective_login));
        return true;
    }
    if normalized.contains("USER_NAME") {
        outcome.result_sets.push(ResultSet::single("", "dbo"));
        return true;
    }
    if normalized.contains("IS_SRVROLEMEMBER")
        || normalized.contains("IS_MEMBER")
        || normalized.contains("HAS_PERMS_BY_NAME")
        || normalized.contains("FN_MY_PERMISSIONS")
    {
        outcome.result_sets.push(ResultSet::single("", "1"));
        return true;
    }
    if normalized.contains("DB_NAME") {
        outcome
            .result_sets
            .push(ResultSet::single("", &session.current_database));
        return true;
    }
    if normalized.contains("SYS.DATABASES") || normalized.contains("SP_DATABASES") {
        outcome.result_sets.push(ResultSet {
            columns: vec!["name".into()],
            rows: personality
                .databases
                .iter()
                .map(|d| vec![Some(d.clone())])
                .collect(),
        });
        return true;
    }
    if normalized.contains("SYS.SERVER_PRINCIPALS")
        || normalized.contains("SYS.SQL_LOGINS")
        || normalized.contains("SP_HELPSRVLOGIN")
    {
        let mut names = vec![
            "sa".to_owned(),
            "##MS_PolicyEventProcessingLogin##".to_owned(),
        ];
        names.extend(personality.logins.iter().map(|l| l.name.clone()));
        names.extend(session.synthetic_logins.clone());
        names.sort();
        names.dedup();
        outcome.result_sets.push(ResultSet {
            columns: vec!["name".into(), "type_desc".into()],
            rows: names
                .into_iter()
                .map(|n| vec![Some(n), Some("SQL_LOGIN".into())])
                .collect(),
        });
        return true;
    }
    if normalized.contains("SYS.SERVERS") || normalized.contains("SP_LINKEDSERVERS") {
        outcome.result_sets.push(ResultSet {
            columns: vec!["name".into(), "product".into()],
            rows: personality
                .linked_servers
                .iter()
                .map(|n| vec![Some(n.clone()), Some("SQL Server".into())])
                .collect(),
        });
        return true;
    }
    if normalized.contains("SYSJOBS") || normalized.contains("SP_HELP_JOB") {
        outcome.result_sets.push(ResultSet {
            columns: vec!["name".into(), "enabled".into()],
            rows: session
                .synthetic_jobs
                .iter()
                .map(|n| vec![Some(n.clone()), Some("1".into())])
                .collect(),
        });
        return true;
    }
    false
}

fn configure(session: &mut SessionState, statement: &str, normalized: &str, outcome: &mut Outcome) {
    let enabled = config_value(statement).is_some_and(|value| value != 0);
    let target = if normalized.contains("XP_CMDSHELL") {
        Some(("xp_cmdshell_enabled", &mut session.xp_cmdshell_enabled))
    } else if normalized.contains("CLR ENABLED") {
        Some(("clr_enabled", &mut session.clr_enabled))
    } else if normalized.contains("OLE AUTOMATION") {
        Some((
            "ole_automation_enabled",
            &mut session.ole_automation_enabled,
        ))
    } else if normalized.contains("AD HOC DISTRIBUTED") {
        Some((
            "ad_hoc_distributed_queries_enabled",
            &mut session.ad_hoc_distributed_queries_enabled,
        ))
    } else {
        None
    };
    if let Some((name, field)) = target {
        if config_value(statement).is_some() {
            let old = *field;
            *field = enabled;
            change(outcome, name, &old.to_string(), &enabled.to_string());
        }
        outcome.result_sets.push(ResultSet {
            columns: vec![
                "name".into(),
                "minimum".into(),
                "maximum".into(),
                "config_value".into(),
                "run_value".into(),
            ],
            rows: vec![vec![
                Some(name.trim_end_matches("_enabled").replace('_', " ")),
                Some("0".into()),
                Some("1".into()),
                Some(u8::from(*field).to_string()),
                Some(u8::from(*field).to_string()),
            ]],
        });
    }
}

fn xp_cmdshell(
    session: &SessionState,
    statement: &str,
    personality: &Personality,
    outcome: &mut Outcome,
) {
    if !session.xp_cmdshell_enabled {
        outcome.error = Some(SqlError { number: 15281, state: 1, class: 16, message: "SQL Server blocked access to procedure 'sys.xp_cmdshell' because this component is turned off as part of the security configuration for this server.".into() });
        return;
    }
    let command = quoted_after(statement, "XP_CMDSHELL").unwrap_or_default();
    let normalized = normalize(&command);
    let lines = if normalized == "WHOAMI" {
        vec![format!(
            "nt service\\{}",
            personality.instance_name.to_lowercase()
        )]
    } else if normalized == "HOSTNAME" {
        vec![personality.server_name.clone()]
    } else if normalized.starts_with("IPCONFIG") {
        vec![
            "Windows IP Configuration".into(),
            String::new(),
            "   IPv4 Address. . . . . . . . . . . : 10.20.30.15".into(),
        ]
    } else if normalized.starts_with("SYSTEMINFO") {
        vec![
            format!("Host Name:                 {}", personality.server_name),
            format!("OS Name:                   {}", personality.os_version),
        ]
    } else if normalized == "DIR" || normalized.starts_with("DIR ") {
        vec![
            " Volume in drive C is OS".into(),
            " Directory of C:\\Program Files\\Microsoft SQL Server".into(),
            "08/12/2026  03:41 AM    <DIR>          MSSQL16.MSSQLSERVER".into(),
        ]
    } else if command.is_empty() {
        vec![]
    } else {
        vec![format!(
            "'{}' is not recognized as an internal or external command, operable program or batch file.",
            command.split_whitespace().next().unwrap_or("command")
        )]
    };
    outcome.result_sets.push(ResultSet {
        columns: vec!["output".into()],
        rows: lines.into_iter().map(|line| vec![Some(line)]).collect(),
    });
}

fn unknown(behavior: UnknownQueryBehavior, outcome: &mut Outcome) {
    match behavior {
        UnknownQueryBehavior::Empty => outcome.result_sets.push(ResultSet {
            columns: vec!["".into()],
            rows: Vec::new(),
        }),
        UnknownQueryBehavior::Success => {}
        UnknownQueryBehavior::SyntaxError => {
            outcome.error = Some(SqlError {
                number: 102,
                state: 1,
                class: 15,
                message: "Incorrect syntax near the submitted statement.".into(),
            })
        }
        UnknownQueryBehavior::PermissionDenied => {
            outcome.error = Some(SqlError {
                number: 229,
                state: 5,
                class: 14,
                message: "The SELECT permission was denied on the object.".into(),
            })
        }
    }
}

fn split_statements(sql: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if quoted && bytes.get(i + 1) == Some(&b'\'') {
                i += 2;
                continue;
            }
            quoted = !quoted;
        } else if bytes[i] == b';' && !quoted {
            parts.push(&sql[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    if start < sql.len() {
        parts.push(&sql[start..]);
    }
    parts
}

fn word_after(input: &str, marker: &str) -> Option<String> {
    let upper = input.to_uppercase();
    let index = upper.find(marker)? + marker.len();
    let tail = input.get(index..)?.trim_start();
    if let Some(stripped) = tail.strip_prefix('[') {
        return stripped.split(']').next().map(ToOwned::to_owned);
    }
    tail.split(|c: char| c.is_whitespace() || c == ';' || c == ',')
        .next()
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn trim_identifier(value: &str) -> String {
    value.trim().trim_matches(['[', ']', '"', '\'']).to_owned()
}

fn quoted_after(input: &str, marker: &str) -> Option<String> {
    let upper = input.to_uppercase();
    let index = upper.find(marker)? + marker.len();
    let tail = input.get(index..)?;
    let start = tail.find('\'')? + 1;
    let bytes = tail.as_bytes();
    let mut result = String::new();
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\'' {
            if bytes.get(i + 1) == Some(&b'\'') {
                result.push('\'');
                i += 2;
                continue;
            }
            return Some(result);
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    None
}

fn config_value(input: &str) -> Option<i64> {
    input
        .rsplit(',')
        .next()?
        .trim()
        .trim_end_matches(';')
        .parse()
        .ok()
}

fn extract_hex_literal(input: &str) -> Option<Vec<u8>> {
    let upper = input.to_uppercase();
    let index = upper.find("0X")? + 2;
    let hex: String = input[index..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.is_empty() || hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn change(outcome: &mut Outcome, property: &str, old: &str, new: &str) {
    if old != new {
        outcome.state_changes.push(StateChange {
            property: property.into(),
            old_value: old.into(),
            new_value: new.into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::login7::LoginRequest;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use uuid::Uuid;

    fn session() -> (SessionState, Personality) {
        let p = Personality::default();
        let login = LoginRequest {
            username: "sa".into(),
            ..LoginRequest::default()
        };
        (
            SessionState::new(
                Uuid::new_v4(),
                1,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                &login,
                &p,
            ),
            p,
        )
    }
    #[test]
    fn stateful_xp_cmdshell_is_synthetic() {
        let (mut s, p) = session();
        let enable = handle_sql(
            &mut s,
            &p,
            "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE",
        );
        assert!(s.xp_cmdshell_enabled);
        assert!(!enable.state_changes.is_empty());
        let run = handle_sql(&mut s, &p, "EXEC xp_cmdshell 'whoami'");
        assert_eq!(run.classification, Classification::XpCmdshell);
        assert!(
            run.result_sets[0].rows[0][0]
                .as_ref()
                .unwrap()
                .contains("mssqlserver")
        );
    }
    #[test]
    fn comments_do_not_hide_classification() {
        assert_eq!(
            classify(
                &normalize("/*x*/ EXEC xp_cmdshell --x\n 'whoami'"),
                &Personality::default()
            ),
            Classification::XpCmdshell
        );
    }
    #[test]
    fn statements_respect_quoted_semicolons() {
        assert_eq!(split_statements("SELECT 'a;b'; SELECT 2").len(), 2);
    }
}
