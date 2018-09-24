use std::{ fs, io, mem };
use std::ops::{ RangeBounds, Bound };
use std::os::unix::io::{ AsRawFd, RawFd };
use libc::{ off_t, size_t, };
use tokio::prelude::*;


#[derive(Debug)]
pub struct SendFile<IO>(io::Result<State<IO>>);

#[derive(Debug)]
enum State<IO> {
    Writing {
        io: IO,
        fd: fs::File,
        offset: off_t,
        count: size_t
    },
    End
}

pub fn sendfile<IO, R>(io: IO, fd: fs::File, range: R)
    -> SendFile<IO>
where
    IO: AsRawFd,
    R: RangeBounds<usize>
{
    let offset = match range.start_bound() {
        Bound::Excluded(&x) | Bound::Included(&x) => x,
        Bound::Unbounded => 0
    };

    let count = match range.end_bound() {
        Bound::Excluded(&y) => y - offset,
        Bound::Included(&y) => y + 1 - offset,
        Bound::Unbounded => match fd.metadata() {
            Ok(metadata) => metadata.len() as _,
            Err(err) => return SendFile(Err(err))
        }
    };

    let offset = offset as _;

    SendFile(Ok(State::Writing { io, fd, offset, count }))
}

impl<IO: AsRawFd> Future for SendFile<IO> {
    type Item = (IO, fs::File);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        #[inline]
        unsafe fn sendfile2(io: RawFd, fd: RawFd, offset: &mut off_t, count: size_t) -> io::Result<size_t> {
            match libc::sendfile(io, fd, offset, count) {
                -1 => Err(io::Error::last_os_error()),
                n => Ok(n as _)
            }
        }

        if self.0.is_err() {
            mem::replace(&mut self.0, Ok(State::End))?;
        }

        match self.0.as_mut() {
            Ok(State::Writing { io, fd, ref mut offset, ref mut count }) => unsafe {
                while *count > 0 {
                    match sendfile2(io.as_raw_fd(), fd.as_raw_fd(), offset, *count) {
                        Ok(n) => *count -= n,
                        Err(ref err) if io::ErrorKind::WouldBlock == err.kind()
                            => return Ok(Async::NotReady),
                        Err(err) => return Err(err)
                    }
                }
            },
            _ => panic!()
        }

        match mem::replace(&mut self.0, Ok(State::End)) {
            Ok(State::Writing { io, fd, .. }) => Ok((io, fd).into()),
            _ => panic!()
        }
    }
}
