#[allow(non_camel_case_types)]
mod tls;

use std::{ mem, io };
use std::os::unix::io::AsRawFd;
pub use self::tls::*;


pub const TCP_ULP: libc::c_int = 31;
pub const SOL_TCP: libc::c_int = 6;
pub const SOL_TLS: libc::c_int = 282;
pub const TLS_1_2_VERSION: libc::c_uint = 0x0303;


pub unsafe fn ktls_start<Fd: AsRawFd>(socket: &mut Fd, info: &tls12_crypto_info_aes_gcm_128) -> io::Result<()> {
    const INFO_SIZE: usize = mem::size_of::<tls12_crypto_info_aes_gcm_128>();

    let socket = socket.as_raw_fd();

    if libc::setsockopt(socket, SOL_TCP, TCP_ULP, b"tls\0".as_ptr() as _, 4) < 0 {
        return Err(io::Error::last_os_error());
    }

    if libc::setsockopt(socket, SOL_TLS, TLS_TX as _, info as *const _ as _, INFO_SIZE as _) < 0 {
        return Err(io::Error::last_os_error());
    }

    if libc::setsockopt(socket, SOL_TLS, TLS_RX as _, info as *const _ as _, INFO_SIZE as _) < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub unsafe fn ktls_send_ctrl_message() {
    // TODO
}

pub unsafe fn ktls_recv_ctrl_message() {
    // TODO
}
