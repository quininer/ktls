pub mod sys;

use std::{ error, fmt };
use std::io::{ self, Read, Write };
use std::os::unix::io::AsRawFd;
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
            if let Err(error) = sys::ktls_start(&mut io, tx, rx) {
                return Err(Error { error, io });
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

#[derive(Debug)]
pub struct Error<IO> {
    pub error: io::Error,
    pub io: IO
}

impl<IO> fmt::Display for Error<IO> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl<IO: fmt::Debug> error::Error for Error<IO> {
    fn description(&self) -> &str {
        self.error.description()
    }

    fn cause(&self) -> Option<&error::Error> {
        Some(&self.error)
    }

    fn source(&self) -> Option<&(error::Error + 'static)> {
        Some(&self.error)
    }
}
