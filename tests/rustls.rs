mod common;

use std::sync::mpsc::Receiver;
use std::io::{ self, BufReader, Cursor };
use std::net::{ TcpListener, Shutdown, SocketAddr };
use rustls::{ Session, ServerSession, ServerConfig, TLSError };
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
use self::common::Stream;


#[test]
fn test_alert() -> io::Result<()> {
    fn run_rustls() -> (SocketAddr, &'static str, &'static str, Receiver<TLSError>) {
        use std::thread;
        use std::sync::Arc;
        use std::sync::mpsc::channel;
        use rustls::internal::pemfile::{ certs, rsa_private_keys };

        const CERT: &str = include_str!("common/end.cert");
        const CHAIN: &str = include_str!("common/end.chain");
        const RSA: &str = include_str!("common/end.rsa");

        let cert = certs(&mut BufReader::new(Cursor::new(CERT))).unwrap();
        let mut keys = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA))).unwrap();

        let mut config = ServerConfig::new(rustls::NoClientAuth::new());
        config.set_single_cert(cert, keys.pop().unwrap())
            .expect("invalid key or certificate");
        let config = Arc::new(config);

        let (send, recv) = channel();
        let (send2, recv2) = channel();

        thread::spawn(move || {
            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let listener = TcpListener::bind(&addr).unwrap();

            send.send(listener.local_addr().unwrap()).unwrap();

            let (mut sock, _) = listener.accept().unwrap();
            let config = config.clone();
            let mut sess = ServerSession::new(&config);

            sess.complete_io(&mut sock).unwrap();

            if sess.wants_write() {
                sess.complete_io(&mut sock).unwrap();
            }

            sess.read_tls(&mut sock).unwrap();
            let err = sess.process_new_packets().unwrap_err();

            send2.send(err).unwrap();
        });

        let addr = recv.recv().unwrap();
        (addr, "localhost", CHAIN, recv2)
    }

    let (addr, hostname, chain, recv2) = run_rustls();
    let chain = BufReader::new(Cursor::new(chain));

    let mut stream = Stream::new(hostname, addr.port(), Some(Box::new(chain) as Box<_>))?;

    let record = Message {
        typ: ContentType::Alert,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Alert(AlertMessagePayload {
            level: AlertLevel::Fatal,
            description: AlertDescription::InternalError
        })
    };

    unsafe {
        ktls::sys::send_ctrl_message(
            stream.io.get_mut(),
            ContentType::Alert.get_u8(),
            &record.take_payload()
        )?;
    }

    stream.io.get_mut().shutdown(Shutdown::Both)?;

    let err = recv2.recv().unwrap();
    assert_eq!(err, TLSError::AlertReceived(AlertDescription::InternalError));

    Ok(())
}
