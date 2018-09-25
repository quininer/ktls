# Linux KTLS for Rust

KTLS is a new feature introduced in Linux 4.13 that performs TLS encryption in the kernel.
This will allow us to implement performance optimizations that were previously impossible.

### Usage

First we need to make sure that kernel module is enabled.

```
> sudo modprobe tls
> modinfo tls
...
```

Then we need to use rustls to handshake.

```rust
use tokio_rustls::TlsConnector;
use tokio_rusktls::KtlsStream;

// ...

let connector = TlsConnector::from(config);

TcpStream::connect(&addr)
	.and_then(|sock| connector.connect(dnsname, sock))
	.and_then(|stream| {
		let (io, session) = stream.into_inner();
		KtlsStream::new(io, session)
			.map_err(|err| err.error)
	})

// ...
```

Please note that `ktls` currently only supports TLS 1.2 and AES-GCM 128.
Other algorithms will return `Error`.

### License

This project is licensed under the MIT license.
