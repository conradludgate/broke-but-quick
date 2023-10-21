use rcgen::{DnType, ExtendedKeyUsagePurpose, GeneralSubtree, NameConstraints};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca = rcgen::Certificate::from_params({
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "ca.broke-but-quick");
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName("broke-but-quick".to_owned())],
            excluded_subtrees: vec![],
        });
        params
    })?;

    let server_cert = rcgen::Certificate::from_params({
        let name = "server.broke-but-quick".to_owned();
        let mut params = rcgen::CertificateParams::new(vec![name.clone()]);
        params.distinguished_name.push(DnType::CommonName, name);
        params.use_authority_key_identifier_extension = true;
        // params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params
    })?;
    let client_cert = rcgen::Certificate::from_params({
        let name = "client.broke-but-quick".to_owned();
        let mut params = rcgen::CertificateParams::new(vec![name.clone()]);
        params.distinguished_name.push(DnType::CommonName, name);
        params.use_authority_key_identifier_extension = true;
        // params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        params
    })?;

    std::fs::create_dir_all("certs")?;
    std::fs::write("certs/ca.pem", ca.serialize_pem()?)?;
    std::fs::write(
        "certs/client.pem",
        client_cert.serialize_pem_with_signer(&ca)?,
    )?;
    std::fs::write(
        "certs/server.pem",
        server_cert.serialize_pem_with_signer(&ca)?,
    )?;
    std::fs::write(
        "certs/client.key.pem",
        client_cert.serialize_private_key_pem(),
    )?;
    std::fs::write(
        "certs/server.key.pem",
        server_cert.serialize_private_key_pem(),
    )?;

    Ok(())
}
