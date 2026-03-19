use cert_printer::PrettyPrinter;
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(name = "cert-printer")]
#[command(about = "Print X.509 certificate information", long_about = None)]
struct Args {
    #[arg(help = "Certificate file to print (DER or PEM format)")]
    certificate: PathBuf,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    let data = fs::read(&args.certificate).map_err(|e| format!("Failed to read file: {}", e))?;

    if data.is_empty() {
        return Err("Empty data".to_string());
    }

    let output = if matches!((data[0], data[1]), (0x30, 0x81..=0x83)) {
        let (_, cert) = parse_x509_certificate(&data)
            .map_err(|e| format!("Error while parsing certificate: {e}"))?;
        format!("{}\n{}", cert.pretty_print(), cert.to_pem())
    } else {
        let pem = Pem::iter_from_buffer(&data)
            .enumerate()
            .next()
            .ok_or("Could not parse as DER or PEM")?
            .1
            .map_err(|e| format!("Error while decoding PEM entry: {e}"))?;
        let (_, cert) = parse_x509_certificate(&pem.contents)
            .map_err(|e| format!("Error while parsing certificate: {e}"))?;
        format!("{}\n{}", cert.pretty_print(), cert.to_pem())
    };

    print!("{}", output);

    Ok(())
}
