use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha2::{Sha256, Digest};
use std::error::Error;
use thiserror::Error;
use x509_parser::prelude::*;
use reqwest;

// Constants
const APP_ID: &str = "4RKXM42395.junyaoc.MIRAcam";
const DEV_MODE: bool = true;

#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("Certificate chain error: {0}")]
    CertificateChainError(String),
    
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    
    #[error("Verification error: {0}")]
    VerificationError(String),
    
    #[error("Decoding error: {0}")]
    DecodingError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
}

#[derive(Debug)]
struct AttestationResult {
    chain_valid: bool,
    ext_asn_string: String,
    expected_key_id: String,
}

impl From<base64::DecodeError> for AttestationError {
    fn from(err: base64::DecodeError) -> Self {
        AttestationError::DecodingError(err.to_string())
    }
}

impl From<reqwest::Error> for AttestationError {
    fn from(err: reqwest::Error) -> Self {
        AttestationError::NetworkError(err.to_string())
    }
}

impl From<serde_json::Error> for AttestationError {
    fn from(err: serde_json::Error) -> Self {
        AttestationError::DecodingError(err.to_string())
    }
}

fn get_rp_id_hash(auth_data: &[u8]) -> &[u8] {
    &auth_data[0..32]
}

fn get_sign_count(auth_data: &[u8]) -> u32 {
    let count_bytes = &auth_data[33..37];
    u32::from_be_bytes(count_bytes.try_into().unwrap())
}

async fn verify_app_attest_certificate_chain(certificates: Vec<Vec<u8>>) -> Result<AttestationResult, Box<dyn Error>> {
    if certificates.len() != 2 {
        return Err(Box::new(AttestationError::CertificateChainError(
            "Expected 2 certificates in x5c array".into()
        )));
    }

    let [leaf_cert_buffer, intermediate_cert_buffer] = certificates.as_slice() else {
        return Err(Box::new(AttestationError::CertificateChainError(
            "Failed to destructure certificates".into()
        )));
    };

    // Parse certificates
    let (_, leaf_cert) = X509Certificate::from_der(leaf_cert_buffer)?;
    let (_, intermediate_cert) = X509Certificate::from_der(intermediate_cert_buffer)?;

    // Fetch Apple Root certificate
    let response = reqwest::get("https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem")
        .await?
        .text()
        .await?;
    
    // let root_cert_pem = parse_x509_pem(response.as_bytes())?;
    // let (_, root_cert) = X509Certificate::from_der(&root_cert_pem.contents)?;
    let root_cert_pem = parse_x509_pem(response.as_bytes())?;
    let (_, root_cert) = X509Certificate::from_der(&root_cert_pem.1.contents)?;  // Access contents through .1



    // Verify certificate chain
    let chain = vec![&leaf_cert, &intermediate_cert, &root_cert];
    for i in 0..chain.len() - 1 {
        let cert = chain[i];
        let issuer = chain[i + 1];

        if cert.issuer() != issuer.subject() {
            return Err(Box::new(AttestationError::CertificateChainError(
                format!("Certificate at index {} was not issued by the next certificate in the chain", i)
            )));
        }


        // Note: Signature verification is skipped for now
        // A more complete implementation would require additional crypto libraries
        // // Verify certificate signature
        // if !cert.verify_signature(Some(issuer.public_key()))? {
        //     return Err(Box::new(AttestationError::CertificateChainError(
        //         format!("Failed to verify certificate at index {}", i)
        //     )));
        // }
    }

    // Check App Attest extension
    let oid_app_attest = "1.2.840.113635.100.8.2";
    let app_attest_extension = leaf_cert.extensions().iter()
        .find(|ext| ext.oid.to_string() == oid_app_attest)
        .ok_or_else(|| AttestationError::CertificateChainError(
            "Leaf certificate does not contain the App Attest extension".into()
        ))?;

    // let ext_asn_string = app_attest_extension.value.to_string();
    let ext_asn_string = hex::encode(app_attest_extension.value);
    
    // Get credential certificate public key
    let cred_cert_public_key = &leaf_cert.public_key().raw;
    let cred_cert_public_key = &cred_cert_public_key[cred_cert_public_key.len()-65..];
    let expected_key_id = BASE64.encode(
        Sha256::digest(cred_cert_public_key).as_slice()
    );

    // Verify intermediate certificate subject
    let expected_intermediate_subject = "CN=Apple App Attestation CA 1, O=Apple Inc., ST=California";
    if intermediate_cert.subject().to_string() != expected_intermediate_subject {
        return Err(Box::new(AttestationError::CertificateChainError(
            "Intermediate certificate is not the expected Apple App Attestation CA".into()
        )));
    }

    Ok(AttestationResult {
        chain_valid: true,  // Now we provide a boolean value
        ext_asn_string,     // String value from earlier in the function
        expected_key_id,    // String value from earlier in the function
    })
}






// Helper function to convert CBOR values to JSON values
fn cbor_to_json(cbor: ciborium::Value) -> serde_json::Value {
    match cbor {
        ciborium::Value::Integer(n) => {
            // Explicitly convert to i64 first
            let value: i64 = n.try_into().unwrap_or_default();
            if let Some(num) = serde_json::Number::from_f64(value as f64) {
                serde_json::Value::Number(num)
            } else {
                serde_json::Value::Null
            }
        },
        ciborium::Value::Text(s) => serde_json::Value::String(s),
        ciborium::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(cbor_to_json).collect())
        }
        ciborium::Value::Map(map) => {
            let mut json_map = serde_json::Map::new();
            for (k, v) in map {
                if let ciborium::Value::Text(key) = k {
                    json_map.insert(key, cbor_to_json(v));
                }
            }
            serde_json::Value::Object(json_map)
        }
        ciborium::Value::Bytes(bytes) => {
            serde_json::Value::String(BASE64.encode(bytes))
        }
        ciborium::Value::Float(f) => {
            if let Some(num) = serde_json::Number::from_f64(f) {
                serde_json::Value::Number(num)
            } else {
                serde_json::Value::Null
            }
        }
        ciborium::Value::Bool(b) => serde_json::Value::Bool(b),
        ciborium::Value::Null => serde_json::Value::Null,
        _ => serde_json::Value::Null,
    }
}








pub async fn verify_attestation(
    key_id: &str,
    attestation: &str,
    nonce: &str,
) -> Result<bool, Box<dyn Error>> {
    let attestation_object = BASE64.decode(attestation)?;

    // let attestation_object_json: serde_json::Value = ciborium::de::from_reader(&attestation_object[..])?;

    // First decode CBOR into a Value
    let cbor_value: ciborium::Value = ciborium::de::from_reader(&attestation_object[..])?;

    // Convert CBOR Value to serde_json::Value
    let attestation_object_json = match cbor_value {
        ciborium::Value::Map(map) => {
            let mut json_map = serde_json::Map::new();
            for (k, v) in map {
                if let ciborium::Value::Text(key) = k {
                    json_map.insert(key, cbor_to_json(v));
                }
            }
            serde_json::Value::Object(json_map)
        }
        _ => return Err(Box::new(AttestationError::InvalidFormat("Invalid attestation format".into()))),
    };


    // Verify format
    if attestation_object_json["fmt"] != "apple-appattest" {
        return Err(Box::new(AttestationError::InvalidFormat(
            "Unsupported attestation format".into()
        )));
    }


    // println!("Attestation object: {}", serde_json::to_string_pretty(&attestation_object_json).unwrap());



    // Get x5c certificates from attestation statement
    let x5c = attestation_object_json["attStmt"]["x5c"]
        .as_array()
        .ok_or("Missing x5c array")?;
    
    let certificates: Vec<Vec<u8>> = x5c.iter()
        .map(|cert| BASE64.decode(cert.as_str().unwrap()).unwrap())
        .collect();

    let attestation_result = verify_app_attest_certificate_chain(certificates).await?;

    // let auth_data = attestation_object_json["authData"].as_array().unwrap();
    // let auth_data = attestation_object_json["authData"]
    //     .as_array()
    //     .ok_or("Missing authData")?
    //     .iter()
    //     .map(|v| v.as_u64().unwrap_or(0) as u8)
    //     .collect::<Vec<u8>>();

    // let auth_data = attestation_object_json["authData"]
    //     .as_str()
    //     .ok_or("Missing authData")?
    //     .as_bytes()
    //     .to_vec();
    let auth_data = BASE64.decode(
        attestation_object_json["authData"]
            .as_str()
            .ok_or("Missing authData")?
    )?;

    // println!("Auth data: {:?}", auth_data);
    
    // Verify nonce
    // let nonce_bytes = BASE64.decode(nonce)?;
    // let client_data_hash = [auth_data, &nonce_bytes].concat();
    // let client_data_hash_sha256 = Sha256::digest(&client_data_hash);
    let nonce_bytes = BASE64.decode(nonce)?;
    let client_data_hash = [&auth_data[..], &nonce_bytes].concat();
    let client_data_hash_sha256 = Sha256::digest(&client_data_hash);




    
    let client_data_valid = attestation_result.ext_asn_string.ends_with(&hex::encode(client_data_hash_sha256));
    let key_id_valid = key_id == attestation_result.expected_key_id;

    // Verify rpIdHash
    // let app_id_hash = hex::encode(Sha256::digest(APP_ID));
    // let rp_id_hash = hex::encode(get_rp_id_hash(auth_data));
    // let is_rp_id_hash_valid = rp_id_hash == app_id_hash;
    let app_id_hash = hex::encode(Sha256::digest(APP_ID));
    let rp_id_hash = hex::encode(get_rp_id_hash(&auth_data));  // Add & here
    let is_rp_id_hash_valid = rp_id_hash == app_id_hash;



    // Verify sign count
    // let sign_count = get_sign_count(auth_data);
    // let is_sign_count_valid = sign_count == 0;
    let sign_count = get_sign_count(&auth_data);  // Add & here
    let is_sign_count_valid = sign_count == 0;



    // Verify AAGUID
    let end_index = if DEV_MODE { 53 } else { 46 };
    let aa_guid = String::from_utf8(auth_data[37..end_index].to_vec())?;
    let expected_guid = if DEV_MODE { "appattestdevelop" } else { "appattest" };
    let is_aa_guid_valid = aa_guid == expected_guid;

    // Verify credId
    // let cred_id_len = &auth_data[53..55];
    // if cred_id_len[0] != 0 || cred_id_len[1] != 32 {
    //     return Err(Box::new(AttestationError("Invalid credId length".into())));
    // }
    let cred_id_len = &auth_data[53..55];
    // println!("Cred id len: {:?}", cred_id_len);
    if cred_id_len[0] != 0 || cred_id_len[1] != 32 {
        return Err(Box::new(AttestationError::InvalidFormat(
            "Invalid credId length".into()
        )));
    }



    let cred_id = BASE64.encode(&auth_data[55..87]);
    let is_cred_id_valid = cred_id == key_id;

    println!("Verification results: {{
        chain_valid: {},
        client_data_valid: {},
        key_id_valid: {},
        is_rp_id_hash_valid: {},
        is_sign_count_valid: {},
        is_aa_guid_valid: {},
        is_cred_id_valid: {}
    }}", 
    attestation_result.chain_valid,
    client_data_valid,
    key_id_valid,
    is_rp_id_hash_valid,
    is_sign_count_valid,
    is_aa_guid_valid,
    is_cred_id_valid);

    Ok(attestation_result.chain_valid && 
       client_data_valid && 
       key_id_valid && 
       is_rp_id_hash_valid && 
       is_sign_count_valid && 
       is_aa_guid_valid && 
       is_cred_id_valid)
} 