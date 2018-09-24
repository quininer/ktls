pub mod sys;

use std::{ error, fmt };
use std::io::{ self, Read, Write };
use std::os::unix::io::{ AsRawFd, RawFd };
pub use crate::sys::tls12_crypto_info_aes_gcm_128 as Tls12CryptoInfoAesGcm128;


#[derive(Debug)]
pub struct KtlsStream<IO> {
    io: IO
}

impl<IO> KtlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> &IO {
        &self.io
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut IO {
        &mut self.io
    }

    #[inline]
    pub fn into_inner(self) -> IO {
        self.io
    }
}

impl<IO> KtlsStream<IO>
where
    IO: Read + Write + AsRawFd
{
    pub fn new(mut io: IO, tx: &Tls12CryptoInfoAesGcm128, rx: &Tls12CryptoInfoAesGcm128)
        -> Result<KtlsStream<IO>, Error<IO>>
    {
        unsafe {
            if let Err(error) = sys::start(&mut io, tx, rx) {
                return Err(Error { error, inner: io });
            }
        }

        Ok(KtlsStream { io })
    }
}

/// TODO(quininer) need buff_size
///
/// TLS records are created and sent after each send() call, unless MSG_MORE is passed. MSG_MORE
/// will delay creation of a record until MSG_MORE is not passed, or the maximum record size is
/// reached or an alert record needs to be sent.
impl<IO: Write> Write for KtlsStream<IO> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

impl<IO: AsRawFd> AsRawFd for KtlsStream<IO> {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.io.as_raw_fd()
    }
}

#[derive(Debug)]
pub struct Error<T> {
    pub error: io::Error,
    pub inner: T
}

impl<T> fmt::Display for Error<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl<T: fmt::Debug> error::Error for Error<T> {
    fn description(&self) -> &str {
        self.error.description()
    }

    fn cause(&self) -> Option<&error::Error> {
        self.source()
    }

    fn source(&self) -> Option<&(error::Error + 'static)> {
        Some(&self.error)
    }
}
