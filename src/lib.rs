pub mod sys;
pub mod codec;

use std::{ error, fmt };
use std::io::{ self, Read, Write };
use std::os::unix::io::{ AsRawFd, RawFd };
use std::marker::PhantomData;
use crate::codec::{ Record, Level, Alert };
pub use crate::sys::tls12_crypto_info_aes_gcm_128 as Tls12CryptoInfoAesGcm128;


#[derive(Debug)]
pub struct KtlsStream<IO, R> {
    io: IO,
    _phantom: PhantomData<R>
}

impl<IO, R> KtlsStream<IO, R> {
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

impl<IO, R> KtlsStream<IO, R>
where
    IO: Read + Write + AsRawFd,
    R: Record
{
    pub fn new(mut io: IO, tx: &Tls12CryptoInfoAesGcm128, rx: &Tls12CryptoInfoAesGcm128)
        -> Result<KtlsStream<IO, R>, Error<IO>>
    {
        unsafe {
            if let Err(error) = sys::start(&mut io, tx, rx) {
                return Err(Error { error, inner: io });
            }
        }

        Ok(KtlsStream { io, _phantom: PhantomData })
    }
}

impl<IO: AsRawFd, R: Record> KtlsStream<IO, R> {
    pub fn send_close_notify(&mut self) -> io::Result<()> {
        const ALERT: u8 = 0x15;

        let record = R::build(Level::Fatal, Alert::CloseNotify);

        unsafe {
            sys::send_ctrl_message(&mut self.io, ALERT, &record)?;
        }

        Ok(())
    }
}

/// TODO(quininer) need buff_size
///
/// TLS records are created and sent after each send() call, unless MSG_MORE is passed. MSG_MORE
/// will delay creation of a record until MSG_MORE is not passed, or the maximum record size is
/// reached or an alert record needs to be sent.
impl<IO: Write, R> Write for KtlsStream<IO, R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

impl<IO, R> Read for KtlsStream<IO, R>
where
    IO: Read + AsRawFd,
    R: Record
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.io.read(buf) {
            Ok(n) => Ok(n),
            Err(ref err) if err.raw_os_error() == Some(5) => {
                let mut buf2 = [0; 16 * 1024];
                let n = unsafe {
                    sys::recv_ctrl_message(&mut self.io, &mut buf2)?
                };

                match R::check(&buf2[..n])? {
                    Some((Level::Fatal, Alert::CloseNotify)) => {
                        let _ = self.send_close_notify();
                        return Ok(0);
                    },
                    Some((Level::Fatal, _)) => return Ok(0),
                    _ => ()
                }

                self.io.read(buf)
            },
            Err(err) => Err(err)
        }
    }
}

impl<IO: AsRawFd, R> AsRawFd for KtlsStream<IO, R> {
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
