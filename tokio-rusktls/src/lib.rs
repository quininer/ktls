pub mod sendfile;

use std::io::{ self, Read, Write };
use std::os::unix::io::{ AsRawFd, RawFd };
use tokio::prelude::*;
use tokio::io::{ AsyncRead, AsyncWrite };
use rustls::{ Session, ClientSession, ServerSession };
use if_chain::if_chain;
use ktls::{ KtlsStream as InnerStream, Tls12CryptoInfoAesGcm128 };


#[derive(Debug)]
pub struct KtlsStream<IO, S> {
    io: InnerStream<IO>,
    session: S,
    is_shutdown: bool
}

impl<IO, S> KtlsStream<IO, S> {
    #[inline]
    pub fn get_ref(&self) -> (&InnerStream<IO>, &S) {
        (&self.io, &self.session)
    }

    #[inline]
    pub fn get_mut(&mut self) -> (&mut InnerStream<IO>, &mut S) {
        (&mut self.io, &mut self.session)
    }

    #[inline]
    pub fn into_inner(self) -> (InnerStream<IO>, S) {
        (self.io, self.session)
    }
}

impl<IO, S> KtlsStream<IO, S>
where
    IO: Read + Write + AsRawFd,
    S: Session + IsClient
{
    pub fn new(io: IO, session: S) -> Result<Self, ktls::Error<(IO, S)>> {
        if session.is_handshaking() {
            return Err(ktls::Error {
                error: io::Error::new(io::ErrorKind::Other, "handshake is not completed."),
                inner: (io, session)
            });
        }

        if_chain! {
            if let Some(rustls::ProtocolVersion::TLSv1_2) = session.get_protocol_version();
            if let Some(scs) = session.get_negotiated_ciphersuite();
            if rustls::BulkAlgorithm::AES_128_GCM == scs.bulk;
            if let Some(secrets) = session.get_secrets();
            then {
                let key_block = secrets.make_key_block(scs.key_block_len());
                let (tx, rx) = Tls12CryptoInfoAesGcm128::from_secrets(
                    <S as IsClient>::FLAG,
                    &key_block,
                    session.get_seq()
                );

                match InnerStream::new(io, &tx, &rx) {
                    Ok(kstream) => Ok(KtlsStream {
                        io: kstream, is_shutdown: false,
                        session
                    }),
                    Err(ktls::Error { error, inner: io }) =>
                        Err(ktls::Error { error, inner: (io, session) })
                }
            } else {
                Err(ktls::Error {
                    error: io::Error::new(io::ErrorKind::Other, "protocol/algorithm is not supported."),
                    inner: (io, session)
                })
            }
        }
    }
}

impl<IO: AsRawFd, S> KtlsStream<IO, S> {
    pub fn send_close_notify(&mut self) -> io::Result<()> {
        use rustls::internal::msgs::{
            alert::AlertMessagePayload,
            message::{
                Message,
                MessagePayload
            },
            enums::{
                ContentType,
                ProtocolVersion,
                AlertLevel,
                AlertDescription
            }
        };

        let record = Message {
            typ: ContentType::Alert,
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Alert(AlertMessagePayload {
                level: AlertLevel::Fatal,
                description: AlertDescription::CloseNotify
            })
        };

        unsafe {
            ktls::sys::send_ctrl_message(
                self.io.get_mut(),
                ContentType::Alert.get_u8(),
                &record.take_payload()
            )?;
        }

        Ok(())
    }
}

impl<IO, S> Read for KtlsStream<IO, S>
where
    IO: Read + Write + AsRawFd,
    S: Session
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.session.wants_read() {
            let n = self.session.read_tls(&mut self.io.get_mut())?;
            self.session.process_new_packets()
                .map_err(|err| {
                    let _ = self.io.flush();
                    io::Error::new(io::ErrorKind::InvalidData, err)
                })?;
            if n == 0 {
                break
            }
        }

        match self.session.read(buf) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                self.is_shutdown = true;
                let _ = self.send_close_notify();
                Ok(0)
            },
            Err(e) => Err(e)
        }
    }
}

impl<IO: Write, S> Write for KtlsStream<IO, S> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

impl<IO, S> AsyncRead for KtlsStream<IO, S>
where
    IO: AsyncRead + AsyncWrite + AsRawFd,
    S: Session
{
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        false
    }
}

impl<IO, S> AsyncWrite for KtlsStream<IO, S>
    where
        IO: AsyncRead + AsyncWrite + AsRawFd,
        S: Session
{
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        macro_rules! try_async {
            ( $op:expr ) => {
                match $op {
                    Ok(n) => n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock =>
                        return Ok(Async::NotReady),
                    Err(e) => return Err(e)
                }
            }
        }

        if !self.is_shutdown {
            try_async!(self.send_close_notify());
            self.is_shutdown = true;
        }

        try_async!(self.io.flush());
        self.io.get_mut().shutdown()
    }
}

impl<IO: AsRawFd, S> AsRawFd for KtlsStream<IO, S> {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.io.as_raw_fd()
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
