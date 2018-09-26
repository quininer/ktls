mod common;

use std::net::ToSocketAddrs;
use webpki::DNSNameRef;
use tokio::prelude::*;
use tokio::io as aio;
use tokio::net::TcpStream;
use tokio::runtime::current_thread;
use tokio_rustls::TlsConnector;
use tokio_rusktls::KtlsStream;
use self::common::get_client_config;


#[test]
fn test_tls12() {
    // https://tls-v1-2.badssl.com:1012/

    let hostname = "tls-v1-2.badssl.com";
    let dnsname = DNSNameRef::try_from_ascii_str(hostname).unwrap();
    let addr = (hostname, 1012)
        .to_socket_addrs().unwrap()
        .next().unwrap();

    let connector = TlsConnector::from(get_client_config());

    let text = format!("\
        GET / HTTP/1.0\r\n\
        Host: {}\r\n\
        Connection: close\r\n\
        \r\n\
    ", hostname);

    let done = TcpStream::connect(&addr)
        .and_then(move |sock| connector.connect(dnsname, sock))
        .and_then(|stream| {
            let (io, session) = stream.into_inner();
            KtlsStream::new(io, &session)
                .map_err(|err| err.error)
        })
        .and_then(|stream| aio::write_all(stream, text.as_bytes()))
        .and_then(|(stream, _)| aio::read_to_end(stream, Vec::new()))
        .map(|(_, buf)| buf);

    let buf = current_thread::block_on_all(done).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.find("<title>tls-v1-2.badssl.com</title>").is_some());
}
