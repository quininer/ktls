mod common;

use std::io::{ self, Read, Write };
use self::common::Stream;


#[test]
fn test_tls12() -> io::Result<()> {
    // https://tls-v1-2.badssl.com:1012/

    let hostname = "tls-v1-2.badssl.com";
    let mut kstream = Stream::new(hostname, 1012, None)?;
    kstream.write(format!("\
        GET / HTTP/1.0\r\n\
        Host: {}\r\n\
        Connection: close\r\n\
        \r\n\
    ", hostname).as_bytes())?;
    let mut output = String::new();
    kstream.read_to_string(&mut output)?;
    let result = output.find("<title>tls-v1-2.badssl.com</title>");
    assert!(result.is_some());

    Ok(())
}
