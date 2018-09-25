use std::io;
use rustls::internal::msgs::{
    codec::Codec,
    message::{
        Message,
        MessagePayload
    },
    enums::{
        ContentType,
        AlertLevel,
        AlertDescription
    }
};
use rustls::{ Session, ClientSession, ServerSession };
use ktls::codec::{ Record, Level, Alert };


#[derive(Debug)]
pub enum Rustls {}

impl Record for Rustls {
    fn build(level: Level, alert: Alert) -> Vec<u8> {
        let level = match level {
            Level::Warning => AlertLevel::Warning,
            Level::Fatal => AlertLevel::Fatal
        };
        let alert = match alert {
            Alert::CloseNotify => AlertDescription::CloseNotify,
            Alert::Other(c) => AlertDescription::Unknown(c)
        };

        Message::build_alert(level, alert).take_payload()
    }

    fn check(buf: &[u8]) -> io::Result<Option<(Level, Alert)>> {
        let record = Message::read_bytes(buf)
            .and_then(|mut record| if record.decode_payload() {
                Some(record)
            } else {
                None
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Unable to decode"))?;

        if let MessagePayload::Alert(payload) = record.payload {
            let level = match payload.level {
                AlertLevel::Fatal => Level::Fatal,
                _ => Level::Warning
            };
            let alert = match payload.description {
                AlertDescription::CloseNotify => Alert::CloseNotify,
                alert => Alert::Other(alert.get_u8())
            };

            return Ok(Some((level, alert)))
        }

        if let ContentType::ApplicationData = record.typ {
            unreachable!("Should not be ApplicationData");
        }

        Ok(None)
    }
}


pub trait IsClient: Session {
    const FLAG: bool;
}

impl IsClient for ClientSession {
    const FLAG: bool = true;
}

impl IsClient for ServerSession {
    const FLAG: bool = false;
}
