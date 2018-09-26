mod common;

use std::{ thread, fs };
use std::net::SocketAddr;
use std::sync::mpsc::channel;
use self::common::{ get_client_config, get_server_config };
use tokio::prelude::*;
use tokio::io as aio;
use tokio::runtime::current_thread;
use tokio::net::{ TcpListener, TcpStream };
use webpki::DNSNameRef;
use tokio_rustls::{ TlsConnector, TlsAcceptor };
use tokio_rusktls::KtlsStream;
use tokio_linux_io as lio;


#[test]
fn test_sendfile() {
    fn run_server() -> SocketAddr {
        let acceptor = TlsAcceptor::from(get_server_config());
        let (send, recv) = channel();

        thread::spawn(move || {
            let addr = SocketAddr::from(([127, 0, 0, 1], 0));
            let listener = TcpListener::bind(&addr).unwrap();

            send.send(listener.local_addr().unwrap()).unwrap();

            let done = listener.incoming()
                .and_then(|sock| acceptor.accept(sock))
                .and_then(|stream| {
                    let (io, session) = stream.into_inner();
                    KtlsStream::new(io, &session)
                        .map_err(|err| err.error)
                })
                .and_then(|stream| aio::read_exact(stream, [0; 3]))
                .and_then(|(stream, buf)| {
                    assert_eq!(&buf, b"aaa");
                    let fd = fs::File::open("Cargo.toml").unwrap();
                    lio::sendfile(stream, fd, ..22)
                })
                .and_then(|(stream, _)| aio::shutdown(stream))
                .for_each(|_| Ok(()));

            current_thread::block_on_all(done).unwrap();
        });

        recv.recv().unwrap()
    }

    let addr = run_server();

    let dnsname = DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let connector = TlsConnector::from(get_client_config());

    let mut fd = fs::File::open("Cargo.toml").unwrap();
    let mut buf = [0; 22];
    fd.read_exact(&mut buf).unwrap();

    let done = TcpStream::connect(&addr)
        .and_then(move |sock| connector.connect(dnsname, sock))
        .and_then(|stream| aio::write_all(stream, b"aaa"))
        .and_then(|(stream, _)| aio::read_to_end(stream, Vec::new()))
        .map(|(_, buf)| buf);

    let buf2 = current_thread::block_on_all(done).unwrap();
    assert_eq!(buf2, buf);
}
