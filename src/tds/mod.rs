pub mod batch;
pub mod login;
pub mod login7;
pub mod packet;
pub mod prelogin;
pub mod rpc;
pub mod tokens;

pub const SQL_BATCH: u8 = 0x01;
pub const RPC: u8 = 0x03;
pub const TABULAR_RESULT: u8 = 0x04;
pub const LOGIN: u8 = 0x02;
pub const LOGIN7: u8 = 0x10;
pub const PRELOGIN: u8 = 0x12;
pub const ATTENTION: u8 = 0x06;
