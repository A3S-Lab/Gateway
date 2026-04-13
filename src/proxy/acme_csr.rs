//! CSR (Certificate Signing Request) building and DER encoding

use crate::error::{GatewayError, Result};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_der_length_short() {
        let mut out = Vec::new();
        encode_der_length(42, &mut out);
        assert_eq!(out, vec![42]);
    }

    #[test]
    fn test_encode_der_length_medium() {
        let mut out = Vec::new();
        encode_der_length(200, &mut out);
        assert_eq!(out, vec![0x81, 200]);
    }

    #[test]
    fn test_encode_der_length_long() {
        let mut out = Vec::new();
        encode_der_length(300, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x2c]);
    }

    #[test]
    fn test_pem_encode() {
        let pem = pem_encode("TEST", &[1, 2, 3, 4]);
        assert!(pem.starts_with("-----BEGIN TEST-----\n"));
        assert!(pem.ends_with("-----END TEST-----\n"));
    }

    #[test]
    fn test_build_csr() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let csr = build_csr(&key, &["example.com".to_string()], &rng).unwrap();
        // CSR should start with SEQUENCE tag
        assert_eq!(csr[0], 0x30);
        assert!(csr.len() > 100);
    }

    #[test]
    fn test_build_csr_multiple_domains() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let domains = vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "api.example.com".to_string(),
        ];
        let csr = build_csr(&key, &domains, &rng).unwrap();
        assert_eq!(csr[0], 0x30);
        // Multi-domain CSR should be larger
        assert!(csr.len() > 150);
    }
}

/// Build a minimal DER-encoded PKCS#10 CSR for the given domains
pub fn build_csr(key: &EcdsaKeyPair, domains: &[String], rng: &SystemRandom) -> Result<Vec<u8>> {
    // Build Subject Alternative Names extension
    let mut san_bytes = Vec::new();
    for domain in domains {
        // GeneralName: dNSName [2] IA5String
        let domain_bytes = domain.as_bytes();
        san_bytes.push(0x82); // context tag [2]
        encode_der_length(domain_bytes.len(), &mut san_bytes);
        san_bytes.extend_from_slice(domain_bytes);
    }

    // Wrap SAN in SEQUENCE
    let mut san_seq = vec![0x30]; // SEQUENCE
    encode_der_length(san_bytes.len(), &mut san_seq);
    san_seq.extend_from_slice(&san_bytes);

    // Extension: subjectAltName (OID 2.5.29.17)
    let san_oid = &[0x55, 0x1d, 0x11]; // 2.5.29.17
    let mut ext = Vec::new();
    // OID
    ext.push(0x06); // OID tag
    encode_der_length(san_oid.len(), &mut ext);
    ext.extend_from_slice(san_oid);
    // OCTET STRING wrapping the SAN SEQUENCE
    ext.push(0x04); // OCTET STRING
    encode_der_length(san_seq.len(), &mut ext);
    ext.extend_from_slice(&san_seq);

    // Wrap extension in SEQUENCE
    let mut ext_seq = vec![0x30];
    encode_der_length(ext.len(), &mut ext_seq);
    ext_seq.extend_from_slice(&ext);

    // Extensions SEQUENCE
    let mut exts_seq = vec![0x30];
    encode_der_length(ext_seq.len(), &mut exts_seq);
    exts_seq.extend_from_slice(&ext_seq);

    // Wrap in SET for extensionRequest attribute
    let mut exts_set = vec![0x31];
    encode_der_length(exts_seq.len(), &mut exts_set);
    exts_set.extend_from_slice(&exts_seq);

    // extensionRequest OID: 1.2.840.113549.1.9.14
    let ext_req_oid = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
    let mut attr = Vec::new();
    attr.push(0x06);
    encode_der_length(ext_req_oid.len(), &mut attr);
    attr.extend_from_slice(ext_req_oid);
    attr.extend_from_slice(&exts_set);

    let mut attr_seq = vec![0x30];
    encode_der_length(attr.len(), &mut attr_seq);
    attr_seq.extend_from_slice(&attr);

    // Attributes [0] IMPLICIT
    let mut attrs = vec![0xa0];
    encode_der_length(attr_seq.len(), &mut attrs);
    attrs.extend_from_slice(&attr_seq);

    // CertificationRequestInfo
    let mut cri = Vec::new();
    // Version: INTEGER 0
    cri.extend_from_slice(&[0x02, 0x01, 0x00]);
    // Subject: empty SEQUENCE (Let's Encrypt ignores subject, uses SAN)
    cri.extend_from_slice(&[0x30, 0x00]);
    // SubjectPublicKeyInfo
    let spki = build_ec_spki(key);
    cri.extend_from_slice(&spki);
    // Attributes
    cri.extend_from_slice(&attrs);

    let mut cri_seq = vec![0x30];
    encode_der_length(cri.len(), &mut cri_seq);
    cri_seq.extend_from_slice(&cri);

    // Sign the CertificationRequestInfo
    let sig = key
        .sign(rng, &cri_seq)
        .map_err(|e| GatewayError::Other(format!("CSR signing failed: {}", e)))?;
    let sig_bytes = sig.as_ref();

    // Build CertificationRequest
    let mut cr = Vec::new();
    cr.extend_from_slice(&cri_seq);
    // SignatureAlgorithm: ecdsaWithSHA256 (1.2.840.10045.4.3.2)
    let sig_alg_oid = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    let mut sig_alg = vec![0x30];
    let mut sig_alg_inner = vec![0x06];
    encode_der_length(sig_alg_oid.len(), &mut sig_alg_inner);
    sig_alg_inner.extend_from_slice(sig_alg_oid);
    encode_der_length(sig_alg_inner.len(), &mut sig_alg);
    sig_alg.extend_from_slice(&sig_alg_inner);
    cr.extend_from_slice(&sig_alg);
    // Signature: BIT STRING
    let mut sig_bits = vec![0x03];
    encode_der_length(sig_bytes.len() + 1, &mut sig_bits);
    sig_bits.push(0x00); // no unused bits
    sig_bits.extend_from_slice(sig_bytes);
    cr.extend_from_slice(&sig_bits);

    let mut csr = vec![0x30];
    encode_der_length(cr.len(), &mut csr);
    csr.extend_from_slice(&cr);

    Ok(csr)
}

/// Build EC SubjectPublicKeyInfo DER for P-256
pub fn build_ec_spki(key: &EcdsaKeyPair) -> Vec<u8> {
    let pub_key = key.public_key().as_ref(); // 65 bytes uncompressed point

    // AlgorithmIdentifier: ecPublicKey + P-256
    let ec_oid = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
    let p256_oid = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7

    let mut alg_id = Vec::new();
    alg_id.push(0x06);
    encode_der_length(ec_oid.len(), &mut alg_id);
    alg_id.extend_from_slice(ec_oid);
    alg_id.push(0x06);
    encode_der_length(p256_oid.len(), &mut alg_id);
    alg_id.extend_from_slice(p256_oid);

    let mut alg_seq = vec![0x30];
    encode_der_length(alg_id.len(), &mut alg_seq);
    alg_seq.extend_from_slice(&alg_id);

    // BIT STRING wrapping the public key
    let mut bit_str = vec![0x03];
    encode_der_length(pub_key.len() + 1, &mut bit_str);
    bit_str.push(0x00); // no unused bits
    bit_str.extend_from_slice(pub_key);

    // SEQUENCE { algorithmIdentifier, subjectPublicKey }
    let mut spki = Vec::new();
    spki.extend_from_slice(&alg_seq);
    spki.extend_from_slice(&bit_str);

    let mut spki_seq = vec![0x30];
    encode_der_length(spki.len(), &mut spki_seq);
    spki_seq.extend_from_slice(&spki);

    spki_seq
}

/// Encode a DER length field
pub fn encode_der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// PEM-encode DER data
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let b64 = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}
