mod common;

use std::thread;
use std::sync::mpsc::{ channel, Receiver };
use std::net::{ TcpListener, SocketAddr };
use tokio::prelude::*;
use tokio::net::TcpStream;
use tokio::runtime::current_thread;
use webpki::DNSNameRef;
use rustls::{ Session, ServerSession, TLSError };
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
use tokio_rustls::TlsConnector;
use tokio_rusktls::KtlsStream;
use self::common::{ get_server_config, get_client_config };


#[test]
fn test_alert() {
    fn run_server() -> (SocketAddr, Receiver<TLSError>) {
        let config = get_server_config();

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
        (addr, recv2)
    }

    let (addr, recv2) = run_server();

    let dnsname = DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let connector = TlsConnector::from(get_client_config());

    let record = Message {
        typ: ContentType::Alert,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Alert(AlertMessagePayload {
            level: AlertLevel::Fatal,
            description: AlertDescription::InternalError
        })
    };

    let done = TcpStream::connect(&addr)
        .and_then(move |sock| connector.connect(dnsname, sock))
        .and_then(|stream| {
            let (io, session) = stream.into_inner();
            KtlsStream::new(io, &session)
                .map_err(|err| err.error)
        })
        .and_then(|stream| unsafe {
            let mut io = stream.into_inner();

            ktls::sys::send_ctrl_message(
                io.get_mut(),
                ContentType::Alert.get_u8(),
                &record.take_payload()
            )
        });

    current_thread::block_on_all(done).unwrap();

    let err = recv2.recv().unwrap();
    assert_eq!(err, TLSError::AlertReceived(AlertDescription::InternalError));
}
