use blake2::{Blake2b, Digest};
use base58::{ToBase58, FromBase58};

#[derive(Debug)]
pub enum ErrDefine {
    InvalidHexPublicKey = 1,
    InvalidSS58Address  = 2,
}

#[derive(Debug)]
pub enum Network {
    Polkadot          = 0,
    PolkadotReserved  = 1,
    Kusama            = 2,
    GenericSubstrate  = 42,
    // Sorry, only support real good project :)
}

pub fn convert_ss58_address_from_hex_public_key(hex_public_key: &str, network: Network) -> Result<String, ErrDefine> {
    let formatted_public_key: &str;

    let key_len = hex_public_key.len();
    if key_len == 66 && hex_public_key.starts_with("0x") {
        formatted_public_key = &hex_public_key[2..key_len];
    } else {
        formatted_public_key = &hex_public_key[..];
    }

    let raw_account_id_res = hex::decode(formatted_public_key);
    match raw_account_id_res {
        Ok(mut raw_account_id) => {
            if raw_account_id.len() == 32 {
                let ss58pre = b"SS58PRE";
                let mut checksum_pre_image: Vec<u8> = Vec::with_capacity(64);
                let address_type = network as u8;
                checksum_pre_image.extend_from_slice(ss58pre);
                checksum_pre_image.push(address_type);
                checksum_pre_image.append(&mut raw_account_id.clone());
                let check_sum = Blake2b::digest(checksum_pre_image.as_slice());

                let mut ss58_pre_image: Vec<u8> = Vec::with_capacity(64);
                ss58_pre_image.push(address_type);
                ss58_pre_image.append(&mut raw_account_id);
                ss58_pre_image.extend_from_slice(&check_sum[0..2]);

                Ok(ss58_pre_image[..].to_base58())
            } else {
                Err(ErrDefine::InvalidHexPublicKey)
            }
        },
        _ => {
            Err(ErrDefine::InvalidHexPublicKey)
        }
    }
}

pub fn convert_hex_public_key_from_ss58_address(ss58_address: &str, add_0x_prefix: bool) -> Result<String, ErrDefine> {
    let res = ss58_address.from_base58();
    match res {
        Ok(address_bytes) => {
            let len = address_bytes.len();
            if len == 35 {
                let public_key = &address_bytes[1..33];
                let hex_public_key = hex::encode(public_key);
                if add_0x_prefix {
                    Ok(format!("0x{}", &hex_public_key))
                } else {
                    Ok(hex_public_key)
                }
            } else {
                Err(ErrDefine::InvalidSS58Address)
            }
        },
        _ => {
            Err(ErrDefine::InvalidSS58Address)
        }
    }
}

#[cfg(test)]
mod tests {
    // cargo test --release -- --nocapture
    use crate::*;
    #[test]
    fn it_works() {
        let public_key = "0x866ed11132a43bc81b68f1ca5e84b15260191c4e6912b31d0825152a9fbc6108";
        let public_key2 = "866ed11132a43bc81b68f1ca5e84b15260191c4e6912b31d0825152a9fbc6108";
        let kusama_ss58 = convert_ss58_address_from_hex_public_key(public_key, Network::Kusama).unwrap();
        let polkadot_ss58 = convert_ss58_address_from_hex_public_key(public_key, Network::Polkadot).unwrap();
        let generic_ss58 = convert_ss58_address_from_hex_public_key(public_key, Network::GenericSubstrate).unwrap();

        assert_eq!(kusama_ss58, "FcarUJykY4Ggh5HG91VxpFVYG11y8SFTGyqmAU2MMqx2rC9");
        assert_eq!(polkadot_ss58, "143GLVEAyxJpNaGMT5FTD1ieFHiRrmBD5PsaXoBRReeyU8zk");
        assert_eq!(generic_ss58, "5F6yC9y78B3Lw3FqVSCT4rtVPfinATd4zu96NWC4sZdTHdNj");

        let kusama_ss58 = convert_ss58_address_from_hex_public_key(public_key2, Network::Kusama).unwrap();
        let polkadot_ss58 = convert_ss58_address_from_hex_public_key(public_key2, Network::Polkadot).unwrap();
        let generic_ss58 = convert_ss58_address_from_hex_public_key(public_key2, Network::GenericSubstrate).unwrap();

        assert_eq!(kusama_ss58, "FcarUJykY4Ggh5HG91VxpFVYG11y8SFTGyqmAU2MMqx2rC9");
        assert_eq!(polkadot_ss58, "143GLVEAyxJpNaGMT5FTD1ieFHiRrmBD5PsaXoBRReeyU8zk");
        assert_eq!(generic_ss58, "5F6yC9y78B3Lw3FqVSCT4rtVPfinATd4zu96NWC4sZdTHdNj");

        assert_eq!(public_key, convert_hex_public_key_from_ss58_address(&kusama_ss58, true).unwrap());
        assert_eq!(public_key, convert_hex_public_key_from_ss58_address(&polkadot_ss58, true).unwrap());
        assert_eq!(public_key, convert_hex_public_key_from_ss58_address(&generic_ss58, true).unwrap());

        if convert_ss58_address_from_hex_public_key("0x866ed11132a43bc81b68f1ca5e84b15260191c4e6912b31d0825152a9fbc610", Network::Kusama).is_err() {
            println!("capture invalid public key");
        }

        if convert_hex_public_key_from_ss58_address("5F6yC9y78B3Lw3FqVSCT4rtVPfinATd4zu96NWC4sZdTHdN", true).is_err() {
            println!("capture invalid ss58 address");
        }
    }
}
