use std::io;


pub trait Record {
    fn build(level: Level, typ: Alert) -> Vec<u8>;
    fn check(buf: &[u8]) -> io::Result<Option<(Level, Alert)>>;
}

#[derive(Debug, Clone, Copy)]
pub enum Level {
    Warning,
    Fatal
}

#[derive(Debug, Clone, Copy)]
pub enum Alert {
    CloseNotify,
    Other(u8)
}
