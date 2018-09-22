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


pub unsafe fn ktls_start<Fd: AsRawFd>(
    socket: &mut Fd,
    tx: &tls12_crypto_info_aes_gcm_128,
    _rx: &tls12_crypto_info_aes_gcm_128
) -> io::Result<()> {
    const INFO_SIZE: usize = mem::size_of::<tls12_crypto_info_aes_gcm_128>();

    let socket = socket.as_raw_fd();

    if libc::setsockopt(socket, SOL_TCP, TCP_ULP, b"tls\0".as_ptr() as _, 4) < 0 {
        return Err(io::Error::last_os_error());
    }

    if libc::setsockopt(socket, SOL_TLS, TLS_TX as _, tx as *const _ as _, INFO_SIZE as _) < 0 {
        return Err(io::Error::last_os_error());
    }

    // TODO TLS_RX
    //
    // if libc::setsockopt(socket, SOL_TLS, TLS_RX as _, rx as *const _ as _, INFO_SIZE as _) < 0 {
    //     return Err(io::Error::last_os_error());
    // }

    Ok(())
}

pub unsafe fn ktls_send_ctrl_message<Fd: AsRawFd>(socket: &mut Fd, record_type: u8, data: &[u8])
    -> io::Result<usize>
{
    unimplemented!()
}

pub unsafe fn ktls_recv_ctrl_message() {
    unimplemented!()
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
