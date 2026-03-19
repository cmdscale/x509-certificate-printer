# cert-printer

A Rust CLI tool that parses and prints X.509 certificate information in both human-readable and PEM formats.

## Usage

```bash
cargo run -- <certificate_file>
```

The tool accepts certificates in DER or PEM format.

## Library Usage

The `cert-printer` crate exposes a `PrettyPrinter` trait:

```rust
use cert_printer::PrettyPrinter;
use x509_parser::prelude::*;

let der_cert = std::fs::read("cert.der")?;
let (_, x509) = parse_x509_certificate(&der_cert)?;

println!("{}", x509.pretty_print());
println!("{}", x509.to_pem());
```

### Trait Methods

- `pretty_print(&self) -> String` - Returns human-readable certificate details
- `to_pem(&self) -> String` - Returns PEM-encoded certificate

## Credits

This code is verbatim taken from [x509-parser/examples/print-cert.rs](https://github.com/rusticata/x509-parser/blob/master/examples/print-cert.rs) and AI-refactored into a library with a CLI interface.
