use rustls::{
    server::AllowAnyAuthenticatedClient, version::TLS13, Certificate, ClientConfig, PrivateKey,
    RootCertStore, ServerConfig,
};

fn ca_store(
    ca_certs: impl IntoIterator<Item = Certificate>,
) -> Result<RootCertStore, rustls::Error> {
    let mut ca_store = RootCertStore::empty();
    for cert in ca_certs {
        ca_store.add(&cert)?;
    }
    Ok(ca_store)
}

pub fn client(
    private_key: PrivateKey,
    client_certs: impl IntoIterator<Item = Certificate>,
    ca_certs: impl IntoIterator<Item = Certificate>,
) -> Result<ClientConfig, rustls::Error> {
    let mut config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(ca_store(ca_certs)?)
        .with_client_auth_cert(client_certs.into_iter().collect(), private_key)?;

    config.alpn_protocols = vec![b"bbq".to_vec()];
    Ok(config)
}

pub fn server(
    private_key: PrivateKey,
    server_certs: impl IntoIterator<Item = Certificate>,
    ca_certs: impl IntoIterator<Item = Certificate>,
) -> Result<ServerConfig, rustls::Error> {
    let mut config = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_client_cert_verifier(AllowAnyAuthenticatedClient::new(ca_store(ca_certs)?).boxed())
        .with_single_cert(server_certs.into_iter().collect(), private_key)?;

    config.alpn_protocols = vec![b"bbq".to_vec()];
    Ok(config)
}
