use std::sync::Arc;
use std::io::{ self, Read, Write, BufRead };
use std::net::TcpStream;
use rustls::{ ALL_CIPHERSUITES, Session, ClientSession, ClientConfig };
use webpki::DNSNameRef;
use ktls::{ KtlsStream, Tls12CryptoInfoAesGcm128 };


pub struct Stream {
    session: ClientSession,
    pub io: KtlsStream<TcpStream>
}

impl Stream {
    pub fn new(hostname: &str, port: u16, pem: Option<Box<BufRead>>) -> io::Result<Self> {
        let dnsname = DNSNameRef::try_from_ascii_str(hostname).unwrap();

        let mut config = ClientConfig::new();
        if let Some(mut pem) = pem {
            config.root_store.add_pem_file(&mut pem).unwrap();
        }
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.ciphersuites.clear();
        config.ciphersuites.push(ALL_CIPHERSUITES[6]);
        config.ciphersuites.push(ALL_CIPHERSUITES[8]);

        let sock = TcpStream::connect(format!("{}:{}", hostname, port))?;
        let sess = ClientSession::new(&Arc::new(config), dnsname);

        Stream::handshake(sess, sock)
    }

    pub fn handshake(mut sess: ClientSession, mut sock: TcpStream) -> io::Result<Stream> {
        loop {
            sess.complete_io(&mut sock)?;

            if sess.wants_write() {
                sess.complete_io(&mut sock)?;
            }

            if let Some(secrets) = sess.get_secrets() {
                let proto = sess.get_protocol_version().unwrap();
                assert_eq!(proto, rustls::ProtocolVersion::TLSv1_2);
                let scs = sess.get_negotiated_ciphersuite().unwrap();
                assert_eq!(scs.bulk, rustls::BulkAlgorithm::AES_128_GCM);

                let key_block = secrets.make_key_block(scs.key_block_len());

                let (tx, rx) =
                    Tls12CryptoInfoAesGcm128::from_secrets(true, &key_block, sess.get_seq());
                let kstream = KtlsStream::new(sock, &tx, &rx)
                    .map_err(|err| err.error)?;

                return Ok(Stream { session: sess, io: kstream })
            }

        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.session.wants_read() {
            self.session.read_tls(&mut self.io.get_mut())?;
            self.session.process_new_packets()
                .map_err(|err| {
                    let _ = self.io.flush();
                    io::Error::new(io::ErrorKind::InvalidData, err)
                })?;
        }

        match self.session.read(buf) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionAborted => Ok(0),
            Err(e) => Err(e)
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.io.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}
