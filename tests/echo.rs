mod common;

use std::{ thread, io };
use std::net::SocketAddr;
use std::sync::mpsc::channel;
use tokio::prelude::*;
use tokio::io as aio;
use tokio::runtime::current_thread;
use tokio::net::{ TcpListener, TcpStream };
use webpki::DNSNameRef;
use tokio_rustls::{ TlsConnector, TlsAcceptor };
use tokio_rusktls::KtlsStream;
use tokio_linux_zio as zio;
use self::common::{ get_client_config, get_server_config, split };


#[test]
fn test_splice() {
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
                .and_then(|kstream| zio::pipe()
                    .map(move |pipes| (pipes, kstream)))
                .and_then(|((pr, pw), kstream)| {
                    let (r, w) = split(kstream);

                    zio::splice(r, pw, None)
                        .map(drop)
                        .select2(zio::splice(pr, w, None).map(drop))
                        .map_err(|res| res.split().0)
                        .map(drop)

                        // ignore rst
                        .or_else(|err| if err.kind() == io::ErrorKind::ConnectionReset {
                            Ok(())
                        } else {
                            Err(err)
                        })
                })
                .for_each(|_| Ok(()));

            current_thread::block_on_all(done).unwrap();
        });

        recv.recv().unwrap()
    }

    let addr = run_server();

    let dnsname = DNSNameRef::try_from_ascii_str("localhost").unwrap();
    let connector = TlsConnector::from(get_client_config());

    let input = b"hello world!";

    let done = TcpStream::connect(&addr)
        .and_then(move |sock| connector.connect(dnsname, sock))
        .and_then(|stream| aio::write_all(stream, input))
        .and_then(|(stream, input)| aio::read_exact(stream, vec![0; input.len()]))
        .map(|(_, buf)| buf);

    let output = current_thread::block_on_all(done).unwrap();
    assert_eq!(output, input);
}
