
use clap::Parser;

#[derive(Debug, Parser)]
pub struct TlsConfig {
    #[clap(env, long, value_name = "KEY_PEM_FILE")]
    tls_key: String,
    #[clap(env, long, value_name = "CERT_PEM_FILE")]
    tls_cert: String
}

impl TlsConfig {
    #[cfg(feature = "openssl")]
    pub fn builder(&self) -> openssl::ssl::SslAcceptorBuilder {
        use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

        let mut ssl_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        ssl_builder.set_private_key_file(self.tls_key.as_str(), SslFiletype::PEM).unwrap();
        ssl_builder.set_certificate_chain_file(self.tls_cert.as_str()).unwrap();
        ssl_builder
    }

    #[cfg(feature = "rustls")]
    pub fn builder(&self) -> rustls::ServerConfig {
        use std::{fs::File, io::BufReader};
        use rustls::{pki_types::PrivateKeyDer, ServerConfig};
        use rustls_pemfile::{certs, pkcs8_private_keys};

        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();

        // init server config builder with safe defaults
        let config = ServerConfig::builder().with_no_client_auth();

        // load TLS key/cert files
        let cert_file = &mut BufReader::new(File::open(self.tls_cert.as_str()).unwrap());
        let key_file = &mut BufReader::new(File::open(self.tls_key.as_str()).unwrap());

        // convert files to key/cert objects
        let cert_chain = certs(cert_file).collect::<Result<Vec<_>, _>>().unwrap();
        let mut keys = pkcs8_private_keys(key_file)
            .map(|key| key.map(PrivateKeyDer::Pkcs8))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // exit if no keys could be parsed
        if keys.is_empty() {
            eprintln!("Could not locate PKCS 8 private keys.");
            std::process::exit(1);
        }

        config.with_single_cert(cert_chain, keys.remove(0)).unwrap()
    }
}