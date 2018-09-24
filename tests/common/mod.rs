#![allow(dead_code)]

use std::sync::Arc;
use std::io::{ BufReader, Cursor };
use rustls::internal::pemfile::{ certs, rsa_private_keys };
use rustls::{ ALL_CIPHERSUITES, ClientConfig, ServerConfig, NoClientAuth };

const CERT: &str = include_str!("end.cert");
const CHAIN: &str = include_str!("end.chain");
const RSA: &str = include_str!("end.rsa");


pub fn get_server_config() -> Arc<ServerConfig> {
    let cert = certs(&mut BufReader::new(Cursor::new(CERT))).unwrap();
    let mut keys = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA))).unwrap();

    let mut config = ServerConfig::new(NoClientAuth::new());
    config.set_single_cert(cert, keys.pop().unwrap())
        .expect("invalid key or certificate");
    Arc::new(config)
}

pub fn get_client_config() -> Arc<ClientConfig> {
    let mut chain = BufReader::new(Cursor::new(CHAIN));

    let mut config = ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config.root_store.add_pem_file(&mut chain).unwrap();
    config.ciphersuites.clear();
    config.ciphersuites.push(ALL_CIPHERSUITES[6]);
    config.ciphersuites.push(ALL_CIPHERSUITES[8]);
    Arc::new(config)
}
