#[allow(non_camel_case_types)]
mod tls;

use std::{ mem, io, ptr };
use std::os::unix::io::AsRawFd;
use byteorder::{ ByteOrder, NetworkEndian };
pub use self::tls::*;


pub const TCP_ULP: libc::c_int = 31;
pub const SOL_TCP: libc::c_int = 6;
pub const SOL_TLS: libc::c_int = 282;
pub const TLS_1_2_VERSION: libc::c_uint = 0x0303;

const CMSG_LEN: usize = mem::size_of::<u8>();

macro_rules! cmsg {
    ( align $len:expr ) => {
        ($len + mem::size_of::<libc::size_t>() - 1) &
            !(mem::size_of::<libc::size_t>() - 1)
    };
    ( space $len:expr ) => {
        cmsg!(align $len) + cmsg!(align mem::size_of::<libc::cmsghdr>())
    };
    ( firsthdr $mhdr:expr ) => {
        if $mhdr.msg_controllen >= mem::size_of::<libc::cmsghdr>() {
            $mhdr.msg_control as *mut _
        } else {
            ptr::null_mut()
        }
    };
    ( data $cmsg:expr ) => {
        $cmsg.add(1) as *mut u8
    };
    ( len $len:expr ) => {
        cmsg!(align mem::size_of::<libc::cmsghdr>()) + $len
    }
}

pub unsafe fn start<Fd: AsRawFd>(
    socket: &mut Fd,
    tx: &tls12_crypto_info_aes_gcm_128,
    rx: &tls12_crypto_info_aes_gcm_128
) -> io::Result<()> {
    const INFO_SIZE: usize = mem::size_of::<tls12_crypto_info_aes_gcm_128>();

    let socket = socket.as_raw_fd();

    if libc::setsockopt(socket, SOL_TCP, TCP_ULP, b"tls\0".as_ptr() as _, 4) < 0 {
        return Err(io::Error::last_os_error());
    }

    if libc::setsockopt(socket, SOL_TLS, TLS_TX as _, tx as *const _ as _, INFO_SIZE as _) < 0 {
        return Err(io::Error::last_os_error());
    }

    if libc::setsockopt(socket, SOL_TLS, TLS_RX as _, rx as *const _ as _, INFO_SIZE as _) < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub unsafe fn send_ctrl_message<Fd: AsRawFd>(socket: &mut Fd, record_type: u8, data: &[u8])
    -> io::Result<usize>
{
    let mut msg: libc::msghdr = mem::zeroed();
    let mut buf = [0; cmsg!(space CMSG_LEN)];
    let mut msg_iov: libc::iovec = mem::uninitialized();

    msg.msg_control = buf.as_mut_ptr() as *mut _;
    msg.msg_controllen = mem::size_of_val(&buf);
    let cmsg: *mut libc::cmsghdr = cmsg!(firsthdr &msg);
    (*cmsg).cmsg_level = SOL_TLS;
    (*cmsg).cmsg_type = TLS_SET_RECORD_TYPE as _;
    (*cmsg).cmsg_len = cmsg!(len CMSG_LEN);
    *cmsg!(data cmsg) = record_type;
    msg.msg_controllen = (*cmsg).cmsg_len;

    msg_iov.iov_base = data.as_ptr() as *mut _;
    msg_iov.iov_len = data.len() as _;
    msg.msg_iov = &mut msg_iov;
    msg.msg_iovlen = 1;

    match libc::sendmsg(socket.as_raw_fd(), &msg, 0) {
        -1 => Err(io::Error::last_os_error()),
        n => Ok(n as _)
    }
}

pub unsafe fn recv_ctrl_message<Fd: AsRawFd>(socket: &mut Fd, record: &mut [u8]) -> io::Result<usize> {
    const HEADER_LENGTH: usize = 5;

    let mut msg: libc::msghdr = mem::zeroed();
    let mut buf = [0; cmsg!(space CMSG_LEN)];
    let mut msg_iov: libc::iovec = mem::uninitialized();

    msg.msg_control = buf.as_mut_ptr() as *mut _;
    msg.msg_controllen = mem::size_of_val(&buf);

    msg_iov.iov_base = record.as_mut_ptr().add(HEADER_LENGTH) as *mut _;
    msg_iov.iov_len = (record.len() - HEADER_LENGTH) as _;

    msg.msg_iov = &mut msg_iov;
    msg.msg_iovlen = 1;

    match libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) {
        -1 => Err(io::Error::last_os_error()),
        n => {
            let cmsg: *mut libc::cmsghdr = cmsg!(firsthdr &msg);
            if (*cmsg).cmsg_level == SOL_TLS && (*cmsg).cmsg_type == TLS_GET_RECORD_TYPE as _ {
                record[0] = *cmsg!(data cmsg);
                record[1] = TLS_1_2_VERSION_MAJOR as _;
                record[2] = TLS_1_2_VERSION_MINOR as _;
                NetworkEndian::write_u16(&mut record[3..][..2], n as u16);
                Ok(n as usize + HEADER_LENGTH)
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "Buffer contains application data"))
            }
        }
    }
}


impl Default for tls_crypto_info {
    fn default() -> Self {
        tls_crypto_info {
            version: TLS_1_2_VERSION as _,
            cipher_type: TLS_CIPHER_AES_GCM_128 as _
        }
    }
}

impl tls12_crypto_info_aes_gcm_128 {
    pub fn from_secrets(is_client: bool, secrets: &[u8], (read_seq, write_seq): (u64, u64)) -> (Self, Self) {
        let (mut tx, mut rx) = (tls12_crypto_info_aes_gcm_128::default(), tls12_crypto_info_aes_gcm_128::default());

        let (client_key, remaining) = secrets.split_at(TLS_CIPHER_AES_GCM_128_KEY_SIZE as _);
        let (server_key, remaining) = remaining.split_at(TLS_CIPHER_AES_GCM_128_KEY_SIZE as _);
        let (client_iv, remaining) = remaining.split_at(TLS_CIPHER_AES_GCM_128_SALT_SIZE as _);
        let (server_iv, remaining) = remaining.split_at(TLS_CIPHER_AES_GCM_128_SALT_SIZE as _);
        let (nonce, _) = remaining.split_at(TLS_CIPHER_AES_GCM_128_IV_SIZE as _);

        tx.key.copy_from_slice(client_key);
        tx.salt.copy_from_slice(client_iv);
        tx.iv.copy_from_slice(nonce);
        NetworkEndian::write_u64(&mut tx.rec_seq, write_seq);

        rx.key.copy_from_slice(server_key);
        rx.salt.copy_from_slice(server_iv);
        rx.iv.copy_from_slice(nonce);
        NetworkEndian::write_u64(&mut rx.rec_seq, read_seq);

        if is_client {
            (tx, rx)
        } else {
            (rx, tx)
        }
    }
}
