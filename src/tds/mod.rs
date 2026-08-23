pub mod all_headers;
pub mod batch;
pub mod bulk;
pub mod data;
pub mod enclave;
pub mod fedauth;
pub mod login;
pub mod login7;
pub mod packet;
pub mod prelogin;
pub mod rpc;
pub mod smp;
pub mod sspi;
pub mod tds5;
pub mod tokens;
pub mod transaction;

pub const SQL_BATCH: u8 = 0x01;
pub const RPC: u8 = 0x03;
pub const TABULAR_RESULT: u8 = 0x04;
pub const LOGIN: u8 = 0x02;
pub const LOGIN7: u8 = 0x10;
pub const PRELOGIN: u8 = 0x12;
pub const ATTENTION: u8 = 0x06;
pub const BULK_LOAD: u8 = 0x07;
pub const FEDAUTH_TOKEN: u8 = 0x08;
pub const TRANSACTION_MANAGER: u8 = 0x0e;
pub const SSPI: u8 = 0x11;
pub const TDS5_NORMAL: u8 = 0x0f;
pub const TDS5_COMMAND_SEQUENCE_LOGIN: u8 = 0x14;

pub fn packet_type_name(packet_type: u8) -> &'static str {
    match packet_type {
        SQL_BATCH => "sql_batch",
        LOGIN => "pre_tds7_login",
        RPC => "rpc",
        TABULAR_RESULT => "tabular_result",
        ATTENTION => "attention",
        BULK_LOAD => "bulk_load",
        FEDAUTH_TOKEN => "federated_authentication_token",
        TRANSACTION_MANAGER => "transaction_manager_request",
        LOGIN7 => "login7",
        SSPI => "sspi",
        PRELOGIN => "prelogin",
        TDS5_NORMAL => "tds5_token_stream",
        0x05 | 0x09..=0x0d => "unused",
        _ => "unknown",
    }
}

/// Pre-TDS7 and ASE TDS 5 packet IDs. Several IDs overlap Microsoft
/// TDS 7 authentication and transaction packet types, so callers must select
/// this table from negotiated protocol state rather than from the byte alone.
pub fn legacy_packet_type_name(packet_type: u8) -> &'static str {
    match packet_type {
        0x01 => "language",
        0x02 => "login",
        0x03 => "rpc",
        0x04 => "response",
        0x05 => "unformatted",
        0x06 => "attention",
        0x07 => "bulk",
        0x08 => "setup",
        0x09 => "close",
        0x0a => "error",
        0x0b => "protocol_acknowledgement",
        0x0c => "echo",
        0x0d => "logout",
        0x0e => "end_parameters",
        0x0f => "normal",
        0x10 => "urgent",
        0x11 => "migrate",
        0x12 => "hello",
        0x13 => "command_sequence_normal",
        0x14 => "command_sequence_login",
        0x15 => "command_sequence_liveness",
        0x16 => "command_sequence_reserved_1",
        0x17 => "command_sequence_reserved_2",
        _ => "unknown",
    }
}

pub fn is_authentication_packet(packet_type: u8) -> bool {
    matches!(packet_type, LOGIN | LOGIN7 | SSPI | FEDAUTH_TOKEN)
}

#[cfg(test)]
mod tests {
    use super::legacy_packet_type_name;

    #[test]
    fn every_published_legacy_packet_type_is_named() {
        for packet_type in 0x01..=0x17 {
            assert_ne!(
                legacy_packet_type_name(packet_type),
                "unknown",
                "packet type 0x{packet_type:02x}"
            );
        }
        assert_eq!(legacy_packet_type_name(0x18), "unknown");
    }
}
