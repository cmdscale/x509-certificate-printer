use std::cmp::min;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use base64::{Engine, engine::general_purpose::STANDARD};
use x509_parser::extensions::GeneralName;
use x509_parser::objects;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;
use x509_parser::signature_algorithm::SignatureAlgorithm;

// This is all taken from https://github.com/rusticata/x509-parser/blob/master/examples/print-cert.rs

fn format_hex_dump(bytes: &[u8], max_len: usize) -> String {
    let m = min(bytes.len(), max_len);
    let hex: String = bytes[..m].iter().map(|b| format!("{:02x}", b)).collect();
    if bytes.len() > max_len {
        format!("{}... <continued>", hex)
    } else {
        hex
    }
}

fn format_oid(oid: &asn1_rs::Oid) -> String {
    match objects::oid2sn(oid, objects::oid_registry()) {
        Ok(s) => s.to_owned(),
        _ => format!("{oid}"),
    }
}

fn format_generalname(gn: &GeneralName) -> String {
    match gn {
        GeneralName::DNSName(name) => format!("DNSName:{name}"),
        GeneralName::DirectoryName(n) => format!("DirName:{n}"),
        GeneralName::EDIPartyName(obj) => format!("EDIPartyName:{obj:?}"),
        GeneralName::IPAddress(n) => format!("IPAddress:{n:?}"),
        GeneralName::OtherName(oid, n) => format!("OtherName:{oid}, {n:?}"),
        GeneralName::RFC822Name(n) => format!("RFC822Name:{n}"),
        GeneralName::RegisteredID(oid) => format!("RegisteredID:{oid}"),
        GeneralName::URI(n) => format!("URI:{n}"),
        GeneralName::X400Address(obj) => format!("X400Address:{obj:?}"),
        GeneralName::Invalid(_, _) => "Invalid".to_string(),
    }
}

fn format_x509_extension(oid: &asn1_rs::Oid, ext: &X509Extension) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "    [crit:{} l:{}] {}: ",
        ext.critical,
        ext.value.len(),
        format_oid(oid)
    )
    .unwrap();
    match ext.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            output.push_str("      X509v3 Authority Key Identifier\n");
            if let Some(key_id) = &aki.key_identifier {
                output.push_str(&format!("        Key Identifier: {key_id:x}\n"));
            }
            if let Some(issuer) = &aki.authority_cert_issuer {
                for name in issuer {
                    output.push_str(&format!("        Cert Issuer: {name}\n"));
                }
            }
            if let Some(serial) = &aki.authority_cert_serial {
                output.push_str(&format!("        Cert Serial: {}\n", format_serial(serial)));
            }
        }
        ParsedExtension::BasicConstraints(bc) => {
            output.push_str(&format!("      X509v3 CA: {}\n", bc.ca));
        }
        ParsedExtension::CRLDistributionPoints(points) => {
            output.push_str("      X509v3 CRL Distribution Points:\n");
            for point in points.iter() {
                if let Some(name) = &point.distribution_point {
                    output.push_str(&format!("        Full Name: {name:?}\n"));
                }
                if let Some(reasons) = &point.reasons {
                    output.push_str(&format!("        Reasons: {reasons}\n"));
                }
                if let Some(crl_issuer) = &point.crl_issuer {
                    output.push_str("        CRL Issuer: ");
                    for gn in crl_issuer {
                        output.push_str(&format!("{} ", format_generalname(gn)));
                    }
                    output.push('\n');
                }
                output.push('\n');
            }
        }
        ParsedExtension::KeyUsage(ku) => {
            output.push_str(&format!("      X509v3 Key Usage: {ku}\n"));
        }
        ParsedExtension::NSCertType(ty) => {
            output.push_str(&format!("      Netscape Cert Type: {ty}\n"));
        }
        ParsedExtension::SubjectAlternativeName(san) => {
            for name in &san.general_names {
                let s = match name {
                    GeneralName::DNSName(s) => format!("DNS:{s}"),
                    GeneralName::IPAddress(bytes) => {
                        let ip = match bytes.len() {
                            4 => {
                                let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                                format!("{ip}")
                            }
                            16 => {
                                let octets: [u8; 16] = (*bytes).try_into().unwrap();
                                let ip = Ipv6Addr::from(octets);
                                format!("{ip}")
                            }
                            l => format!("invalid (len={l})"),
                        };
                        format!("IP Address:{ip}")
                    }
                    _ => format!("{name:?}"),
                };
                output.push_str(&format!("      X509v3 SAN: {s}\n"));
            }
        }
        ParsedExtension::SubjectKeyIdentifier(subject_key_id) => {
            output.push_str(&format!(
                "      X509v3 Subject Key Identifier: {}\n",
                hex::encode(subject_key_id.0)
            ));
        }
        x => output.push_str(&format!("      {x:?}\n")),
    }
    output
}

fn format_x509_digest_algorithm(alg: &AlgorithmIdentifier, level: usize) -> String {
    let mut output = String::new();
    let indent = " ".repeat(level);
    writeln!(output, "{}Oid: {}", indent, format_oid(&alg.algorithm)).unwrap();
    if let Some(parameter) = &alg.parameters {
        let s = match parameter.tag() {
            asn1_rs::Tag::Oid => {
                let oid = parameter.as_oid().unwrap();
                format_oid(&oid)
            }
            _ => format!("{}", parameter.tag()),
        };
        writeln!(output, "{}Parameter: <PRESENT> {}", indent, s).unwrap();
        let bytes = parameter.as_bytes();
        output.push_str(&format_hex_dump(bytes, 32));
    } else {
        output.push_str(&format!("{}Parameter: <ABSENT>", indent));
    }
    output
}

fn format_serial(b: &[u8]) -> String {
    b.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_number_to_hex_with_colon(b: &[u8], row_size: usize) -> Vec<String> {
    let mut v = Vec::with_capacity(1 + b.len() / row_size);
    for r in b.chunks(row_size) {
        let s = r.iter().fold(String::with_capacity(3 * r.len()), |a, b| {
            a + &format!("{b:02x}:")
        });
        v.push(s)
    }
    v
}

pub trait PrettyPrinter {
    fn pretty_print(&self) -> String;
    fn to_pem(&self) -> String;
}

impl PrettyPrinter for X509Certificate<'_> {
    fn pretty_print(&self) -> String {
        format_x509_info(self)
    }

    fn to_pem(&self) -> String {
        let encoded = STANDARD.encode(self.as_raw());
        let lines: Vec<String> = encoded
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap().to_string())
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            lines.join("\n")
        )
    }
}

fn format_x509_info(x509: &X509Certificate) -> String {
    let mut output = String::new();

    let version = x509.version();
    if version.0 < 3 {
        writeln!(output, "  Version: {}", version).unwrap();
    } else {
        writeln!(output, "  Version: INVALID({})", version.0).unwrap();
    }
    writeln!(
        output,
        "  Serial: {}",
        x509.tbs_certificate.raw_serial_as_string()
    )
    .unwrap();
    writeln!(output, "  Subject: {}", x509.subject()).unwrap();
    writeln!(output, "  Issuer: {}", x509.issuer()).unwrap();
    output.push_str("  Validity:\n");
    writeln!(output, "    NotBefore: {}", x509.validity().not_before).unwrap();
    writeln!(output, "    NotAfter:  {}", x509.validity().not_after).unwrap();
    writeln!(output, "    is_valid:  {}", x509.validity().is_valid()).unwrap();
    output.push_str("  Subject Public Key Info:\n");
    output.push_str(&format_x509_ski(x509.public_key()));
    output.push_str(&format_x509_signature_algorithm(
        &x509.signature_algorithm,
        4,
    ));

    output.push_str("  Signature Value:\n");
    let sig_bytes: &[u8] = match &x509.signature_value.data {
        std::borrow::Cow::Borrowed(b) => b,
        std::borrow::Cow::Owned(v) => v.as_slice(),
    };
    for l in format_number_to_hex_with_colon(sig_bytes, 16) {
        writeln!(output, "      {l}").unwrap();
    }
    output.push_str("  Extensions:\n");
    for ext in x509.extensions() {
        output.push_str(&format_x509_extension(&ext.oid, ext));
    }
    output.push('\n');
    output
}

fn format_x509_signature_algorithm(
    signature_algorithm: &AlgorithmIdentifier,
    indent: usize,
) -> String {
    let mut output = String::new();
    match SignatureAlgorithm::try_from(signature_algorithm) {
        Ok(sig_alg) => {
            output.push_str("  Signature Algorithm: ");
            match sig_alg {
                SignatureAlgorithm::DSA => output.push_str("DSA\n"),
                SignatureAlgorithm::ECDSA => output.push_str("ECDSA\n"),
                SignatureAlgorithm::ED25519 => output.push_str("ED25519\n"),
                SignatureAlgorithm::RSA => output.push_str("RSA\n"),
                SignatureAlgorithm::RSASSA_PSS(params) => {
                    output.push_str("RSASSA-PSS\n");
                    let indent_s = " ".repeat(indent + 2);
                    output.push_str(&format!(
                        "{}Hash Algorithm: {}\n",
                        indent_s,
                        format_oid(params.hash_algorithm_oid()),
                    ));
                    output.push_str(&format!("{}Mask Generation Function: ", indent_s));
                    if let Ok(mask_gen) = params.mask_gen_algorithm() {
                        output.push_str(&format!(
                            "{}/{}\n",
                            format_oid(&mask_gen.mgf),
                            format_oid(&mask_gen.hash),
                        ));
                    } else {
                        output.push_str("INVALID\n");
                    }
                    output.push_str(&format!(
                        "{}Salt Length: {}\n",
                        indent_s,
                        params.salt_length()
                    ));
                }
                SignatureAlgorithm::RSAAES_OAEP(params) => {
                    output.push_str("RSAAES-OAEP\n");
                    let indent_s = " ".repeat(indent + 2);
                    output.push_str(&format!(
                        "{}Hash Algorithm: {}\n",
                        indent_s,
                        format_oid(params.hash_algorithm_oid()),
                    ));
                    output.push_str(&format!("{}Mask Generation Function: ", indent_s));
                    if let Ok(mask_gen) = params.mask_gen_algorithm() {
                        output.push_str(&format!(
                            "{}/{}\n",
                            format_oid(&mask_gen.mgf),
                            format_oid(&mask_gen.hash),
                        ));
                    } else {
                        output.push_str("INVALID\n");
                    }
                    output.push_str(&format!(
                        "{}pSourceFunc: {}\n",
                        indent_s,
                        format_oid(&params.p_source_alg().algorithm),
                    ));
                }
            }
        }
        Err(e) => {
            output.push_str(&format!("Could not parse signature algorithm: {e}\n"));
            output.push_str("  Signature Algorithm:\n");
            output.push_str(&format_x509_digest_algorithm(signature_algorithm, indent));
        }
    }
    output
}

fn format_x509_ski(public_key: &SubjectPublicKeyInfo) -> String {
    let mut output = String::new();
    output.push_str("    Public Key Algorithm:\n");
    output.push_str(&format_x509_digest_algorithm(&public_key.algorithm, 6));
    output.push('\n');
    match public_key.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            output.push_str(&format!("    RSA Public Key: ({} bit)\n", rsa.key_size()));
            for l in format_number_to_hex_with_colon(rsa.modulus, 16) {
                output.push_str(&format!("        {l}\n"));
            }
            if let Ok(e) = rsa.try_exponent() {
                output.push_str(&format!("    exponent: 0x{e:x} ({e})\n"));
            } else {
                output.push_str("    exponent: <INVALID>:\n");
                output.push_str(&format_hex_dump(rsa.exponent, 32));
                output.push('\n');
            }
        }
        Ok(PublicKey::EC(ec)) => {
            output.push_str(&format!("    EC Public Key: ({} bit)\n", ec.key_size()));
            for l in format_number_to_hex_with_colon(ec.data(), 16) {
                output.push_str(&format!("        {l}\n"));
            }
        }
        Ok(PublicKey::DSA(y)) => {
            output.push_str(&format!("    DSA Public Key: ({} bit)\n", 8 * y.len()));
            for l in format_number_to_hex_with_colon(y, 16) {
                output.push_str(&format!("        {l}\n"));
            }
        }
        Ok(PublicKey::GostR3410(y)) => {
            output.push_str(&format!(
                "    GOST R 34.10-94 Public Key: ({} bit)\n",
                8 * y.len()
            ));
            for l in format_number_to_hex_with_colon(y, 16) {
                output.push_str(&format!("        {l}\n"));
            }
        }
        Ok(PublicKey::GostR3410_2012(y)) => {
            output.push_str(&format!(
                "    GOST R 34.10-2012 Public Key: ({} bit)\n",
                8 * y.len()
            ));
            for l in format_number_to_hex_with_colon(y, 16) {
                output.push_str(&format!("        {l}\n"));
            }
        }
        Ok(PublicKey::Unknown(b)) => {
            output.push_str("    Unknown key type\n");
            output.push_str(&format_hex_dump(b, 256));
            output.push('\n');
        }
        Err(_) => {
            output.push_str("    INVALID PUBLIC KEY\n");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::parse_x509_certificate;

    #[test]
    fn pretty_print_with_invalid_certificate_returns_error() {
        let invalid_der = vec![0x30, 0x82, 0x01, 0xff];
        let result = parse_x509_certificate(&invalid_der);
        assert!(result.is_err());
    }

    #[test]
    fn pretty_print_with_valid_certificate_succeeds() {
        let der_cert = hex::decode("308204263082028ea003020102021100e3c99a0ad2a86c42bd9384e972d09952300d06092a864886f70d01010b05003073311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131243022060355040b0c1b74696c6c69407a757365202854696c6d616e204261756d616e6e29312b302906035504030c226d6b636572742074696c6c69407a757365202854696c6d616e204261756d616e6e29301e170d3236303330353131333234375a170d3238303630353130333234375a304f31273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531243022060355040b0c1b74696c6c69407a757365202854696c6d616e204261756d616e6e2930820122300d06092a864886f70d01010105000382010f003082010a0282010100a36f6785351ad9fd76436b2ce650be1662849b8e21aa68b2c23f4f3bf38a1eb9abf983a653b0d807cc9d0d1b37d313aa1a90a815e531d1dfb2c790bc547090fb9c35bc77df437421a3a2c1ba18013aedfdb65b038acdb8a26719bd18111219db47f8ca6db4e090dad717722f2c0c59725562a3eae2ce6c3996232562ccda4f95c8b64e2da31526dc7f4bdca753a9023a6494a4b7dda11e278af6b917fe0fa6de568ebb03ab801b8272396e2ce4098b1ee8059c666e654237f4d470b9e53ba1c0fc46df54f9dd469cb415091b99186a10e9f378d5074d3fb4aa73bc561326e142e60eed93396ac0bb5040cc8df5c7f81e8bd0594c6e4d06b050664627c33fa3f90203010001a3593057300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d230418301680142e997fa48849b3d77b61d74d24c8b999ada1fa62300f0603551d1104083006820474657374300d06092a864886f70d01010b05000382018100b0e65c60ddbace88d4fbadfdef32165381555e83522036a46af625a28cdf331754c7e08a8603b019d5b09aa3b13629a5cd8c0784787b607d04b4c42e47f8983a35f69d082d8feba9c625de3f7ef793837fc045e3358a24249717ae393da23c516343ed3784edf82684e9f1c6394b0b28a9cf869260296ba893815488d19dae49cfa9557135b6450891601118996d03f3c90ba6409deb4ea7bd07e7288ff8575382f28e0837a13fb0fa860cd7880b80f7253c936955a803d5110f384163d4292c9f1e3c413ae2a3b018ae3daef136c1b9bd5888bf8702717e36f85d7bb7b79306bccd6aa4b0206ff903bd6e6d61eaad2d5c62b9417308176faf8a08bac86a5fc42009a418567d1fd0e26eb187a8c7b4208747b62beb81b0284868335d6ea95b2253c4f6203f4e1c2c8d3f0e0075ba7c5b0a92d961425d8c15f1112dc7df857d77904bbc850883c3404067a872a4bae988d954ba9001ac99b75ef7b917b527528fb1a9b54bd17ecd7537f70086ed070e9a2d8e0d83f19b148d1b941456f7283c9b").unwrap();

        let (_, x509) = parse_x509_certificate(&der_cert).unwrap();
        
        let output = x509.pretty_print();
        assert!(output.contains("Subject:"));
        assert!(output.contains("Issuer:"));
        assert!(output.contains("Serial:"));
    }

    #[test]
    fn to_pem_with_valid_certificate_succeeds() {
        let der_cert = hex::decode("308204263082028ea003020102021100e3c99a0ad2a86c42bd9384e972d09952300d06092a864886f70d01010b05003073311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131243022060355040b0c1b74696c6c69407a757365202854696c6d616e204261756d616e6e29312b302906035504030c226d6b636572742074696c6c69407a757365202854696c6d616e204261756d616e6e29301e170d3236303330353131333234375a170d3238303630353130333234375a304f31273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531243022060355040b0c1b74696c6c69407a757365202854696c6d616e204261756d616e6e2930820122300d06092a864886f70d01010105000382010f003082010a0282010100a36f6785351ad9fd76436b2ce650be1662849b8e21aa68b2c23f4f3bf38a1eb9abf983a653b0d807cc9d0d1b37d313aa1a90a815e531d1dfb2c790bc547090fb9c35bc77df437421a3a2c1ba18013aedfdb65b038acdb8a26719bd18111219db47f8ca6db4e090dad717722f2c0c59725562a3eae2ce6c3996232562ccda4f95c8b64e2da31526dc7f4bdca753a9023a6494a4b7dda11e278af6b917fe0fa6de568ebb03ab801b8272396e2ce4098b1ee8059c666e654237f4d470b9e53ba1c0fc46df54f9dd469cb415091b99186a10e9f378d5074d3fb4aa73bc561326e142e60eed93396ac0bb5040cc8df5c7f81e8bd0594c6e4d06b050664627c33fa3f90203010001a3593057300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d230418301680142e997fa48849b3d77b61d74d24c8b999ada1fa62300f0603551d1104083006820474657374300d06092a864886f70d01010b05000382018100b0e65c60ddbace88d4fbadfdef32165381555e83522036a46af625a28cdf331754c7e08a8603b019d5b09aa3b13629a5cd8c0784787b607d04b4c42e47f8983a35f69d082d8feba9c625de3f7ef793837fc045e3358a24249717ae393da23c516343ed3784edf82684e9f1c6394b0b28a9cf869260296ba893815488d19dae49cfa9557135b6450891601118996d03f3c90ba6409deb4ea7bd07e7288ff8575382f28e0837a13fb0fa860cd7880b80f7253c936955a803d5110f384163d4292c9f1e3c413ae2a3b018ae3daef136c1b9bd5888bf8702717e36f85d7bb7b79306bccd6aa4b0206ff903bd6e6d61eaad2d5c62b9417308176faf8a08bac86a5fc42009a418567d1fd0e26eb187a8c7b4208747b62beb81b0284868335d6ea95b2253c4f6203f4e1c2c8d3f0e0075ba7c5b0a92d961425d8c15f1112dc7df857d77904bbc850883c3404067a872a4bae988d954ba9001ac99b75ef7b917b527528fb1a9b54bd17ecd7537f70086ed070e9a2d8e0d83f19b148d1b941456f7283c9b").unwrap();

        let (_, x509) = parse_x509_certificate(&der_cert).unwrap();
        let pem = x509.to_pem();

        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }
}
