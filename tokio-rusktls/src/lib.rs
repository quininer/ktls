mod common;
pub mod sendfile;

use std::io::{ self, Read, Write };
use std::os::unix::io::{ AsRawFd, RawFd };
use bytes::Buf;
use tokio::prelude::*;
use tokio::io::{ AsyncRead, AsyncWrite };
use rustls::Session;
use if_chain::if_chain;
use ktls::{ KtlsStream as InnerStream, Tls12CryptoInfoAesGcm128 };
use crate::common::{ Rustls, IsClient };


#[derive(Debug)]
pub struct KtlsStream<IO> {
    io: InnerStream<IO, Rustls>,
    is_shutdown: bool
}

impl<IO> KtlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> &InnerStream<IO, Rustls> {
        &self.io
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut InnerStream<IO, Rustls> {
        &mut self.io
    }

    #[inline]
    pub fn into_inner(self) -> InnerStream<IO, Rustls> {
        self.io
    }
}

impl<IO> KtlsStream<IO>
where
    IO: Read + Write + AsRawFd,
{
    pub fn new<S>(io: IO, session: &mut S)
        -> Result<Self, ktls::Error<IO>>
        where S: Session + IsClient
    {
        if session.is_handshaking() {
            return Err(ktls::Error {
                error: io::Error::new(io::ErrorKind::Other, "handshake is not completed."),
                inner: io
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

                let kstream =  InnerStream::new(io, &tx, &rx)?;
                Ok(KtlsStream { io: kstream, is_shutdown: false })
            } else {
                Err(ktls::Error {
                    error: io::Error::new(io::ErrorKind::Other, "protocol/algorithm is not supported."),
                    inner: io
                })
            }
        }
    }
}

impl<IO: AsRawFd> KtlsStream<IO> {
    pub fn send_close_notify(&mut self) -> io::Result<()> {
        self.io.send_close_notify()
    }
}

impl<IO> Read for KtlsStream<IO>
where
    IO: Read + Write + AsRawFd,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.io.read(buf)
    }
}

impl<IO: Write> Write for KtlsStream<IO> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io.write(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

impl<IO> AsyncRead for KtlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + AsRawFd,
{
    unsafe fn prepare_uninitialized_buffer(&self, _: &mut [u8]) -> bool {
        false
    }
}

impl<IO> AsyncWrite for KtlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + AsRawFd,
{
    fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        self.io.get_mut().write_buf(buf)
    }

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

impl<IO: AsRawFd> AsRawFd for KtlsStream<IO> {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.io.as_raw_fd()
    }
}
