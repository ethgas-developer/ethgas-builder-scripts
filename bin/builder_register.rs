use commit_boost::prelude::*;
use commit_boost::prelude::tree_hash::TreeHash;
use blst::min_pk::{SecretKey, PublicKey, Signature};
pub type BlsSecretKey = blst::min_pk::SecretKey;
use alloy::{
    primitives::{B256, FixedBytes}, signers::{local::PrivateKeySigner, Signer}, sol, sol_types::{eip712_domain, SolStruct},
    rpc::types::beacon::{constants::BLS_DST_SIG, BlsPublicKey, BlsSignature}, hex
};
use eyre::Result;
use lazy_static::lazy_static;
use prometheus::{IntCounter, Registry};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use std::{
    time::Duration, error::Error, env, str::FromStr
};
use reqwest::{Client, Url};
use tokio_retry::{Retry, strategy::FixedInterval};
use hex::{decode, encode};
use dotenv::dotenv;
use tracing_subscriber::FmtSubscriber;
// use serde_json::Value;

struct EthgasExchangeService {
    exchange_api_base: String,
    eoa_signing_key: B256,
}

struct EthgasBuilderService {
    exchange_api_base: String,
    access_jwt: String,
    bls_secret_key: SecretKey, 
    bls_pubkey: BlsPublicKey,
    chain: Chain,
    enable_registration: bool
}

#[derive(Debug, TreeHash, Deserialize)]
struct RegisteredInfo {
    eoaAddress: alloy::primitives::Address,
}

#[derive(Debug, TreeHash, Deserialize)]
struct SigningData {
    object_root: [u8; 32],
    signing_domain: [u8; 32],
}

#[derive(Debug, Deserialize)]
struct Domain {
    name: String,
    version: String,
    chainId: u64,
    verifyingContract: alloy::primitives::Address
}

#[derive(Debug, Deserialize)]
struct Message {
    hash: String,
    message: String,
    domain: String
}

sol! {
    #[allow(missing_docs)]
    #[derive(Serialize)]
    struct data {
        string hash;
        string message;
        string domain;
    }
}

#[derive(Debug, Deserialize)]
struct Eip712Message {
    message: Message,
    domain: Domain
}

#[derive(Debug, Deserialize)]
struct APILoginResponse {
    success: bool,
    data: APILoginResponseData
}

#[derive(Debug, Deserialize)]
struct APILoginResponseData {
    eip712Message: String,
}

#[derive(Debug, Deserialize)]
struct APILoginVerifyResponse {
    success: bool,
    data: APILoginVerifyResponseData
}

#[derive(Debug, Deserialize)]
struct APILoginVerifyResponseData {
    accessToken: AccessToken
}

#[derive(Debug, Deserialize)]
struct AccessToken {
    token: String
}

#[derive(Debug, Deserialize)]
struct APIBuilderRegisterResponse {
    success: bool,
    data: APIBuilderRegisterResponseData
}

#[derive(Debug, Deserialize)]
struct APIBuilderRegisterResponseData {
    available: bool,
    verified: bool,
    message: Option<RegisteredInfo>
}

#[derive(Debug, Deserialize)]
struct APIBuilderDeregisterResponse {
    success: bool,
    data: APIBuilderDeregisterResponseData
}

#[derive(Debug, Deserialize)]
struct APIBuilderDeregisterResponseData {
    message: Option<RegisteredInfo>
}

#[derive(Debug, Deserialize)]
struct APIBuilderVerifyResponse {
    success: bool,
    data: APIBuilderVerifyResponseData
}

#[derive(Debug, Deserialize)]
struct APIBuilderVerifyResponseData {
    result: usize,
    description: String
}

impl EthgasExchangeService {
    pub async fn login(self) -> Result<String> {
        let client = Client::new();
        let signer = PrivateKeySigner::from_bytes(&self.eoa_signing_key)
            .map_err(|e| eyre::eyre!("Failed to create signer: {}", e))?;
        info!("your EOA address: {}", signer.clone().address());
        let mut exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/user/login"))?;
        let mut res = client.post(exchange_api_url.to_string())
                .query(&[("addr", signer.clone().address())])
                .send()
                .await?;
                
        let res_json_login = res.json::<APILoginResponse>().await?;
        info!(exchange_login_eip712_message = ?res_json_login);
        
        let eip712_message: Eip712Message = serde_json::from_str(&res_json_login.data.eip712Message)
            .map_err(|e| eyre::eyre!("Failed to parse EIP712 message: {}", e))?;
        let eip712_domain_from_api = eip712_message.domain;
        let eip712_sub_message = eip712_message.message;
        let domain = eip712_domain! {
            name: eip712_domain_from_api.name,
            version: eip712_domain_from_api.version,
            chain_id: eip712_domain_from_api.chainId,
            verifying_contract: eip712_domain_from_api.verifyingContract,
        };
        let message = data {
            hash: eip712_sub_message.hash.clone(),
            message: eip712_sub_message.message,
            domain: eip712_sub_message.domain
        };
        let hash = message.eip712_signing_hash(&domain);
        let signature = signer.clone().sign_hash(&hash).await?;
        let signature_hex = encode(signature.as_bytes());
        exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/user/login/verify"))?;
        res = client.post(exchange_api_url.to_string())
                .header("User-Agent", "cb_ethgas_commit")
                .query(&[("addr", signer.clone().address())])
                .query(&[("nonceHash", eip712_sub_message.hash)])
                .query(&[("signature", signature_hex)])
                .send()
                .await?;
        let res_text_login_verify = res.text().await?;
        let res_json_verify: APILoginVerifyResponse = serde_json::from_str(&res_text_login_verify)
            .expect("Failed to parse login verification response");
        info!("successfully obtain JWT from the exchange");
        Ok(res_json_verify.data.accessToken.token)
        // println!("API Response as JSON: {}", res.json::<Value>().await?);
        // Ok(String::from("test"))
    }
}

// Refer to https://github.com/Commit-Boost/commit-boost-client
pub type ForkVersion = [u8; 4];
pub const COMMIT_BOOST_DOMAIN: [u8; 4] = [109, 109, 111, 67];
pub const GENESIS_VALIDATORS_ROOT: [u8; 32] = [0; 32];

#[derive(Copy, Clone)]
pub enum Chain {
    Mainnet,
    Holesky,
    Hoodi
}
impl Chain {
    pub fn genesis_fork_version(&self) -> ForkVersion {
        match self {
            Chain::Mainnet => hex!("00000000"),
            Chain::Holesky => hex!("01017000"),
            Chain::Hoodi => hex!("10000910"),
        }
    }
}

// Refer to https://github.com/Commit-Boost/commit-boost-client
struct CommitBoostSigningService;

impl CommitBoostSigningService {
    pub fn compute_domain(&self, chain: Chain, domain_mask: [u8; 4]) -> [u8; 32] {
        #[derive(Debug, TreeHash)]
        struct ForkData {
            fork_version: [u8; 4],
            genesis_validators_root: [u8; 32],
        }
    
        let mut domain = [0u8; 32];
        domain[..4].copy_from_slice(&domain_mask);
    
        let fork_version = chain.genesis_fork_version();
        let fd = ForkData { fork_version, genesis_validators_root: GENESIS_VALIDATORS_ROOT };
        let fork_data_root = fd.tree_hash_root();
    
        domain[4..].copy_from_slice(&fork_data_root[..28]);
    
        domain
    }

    pub fn compute_signing_root(&self, object_root: [u8; 32], signing_domain: [u8; 32]) -> [u8; 32] {
        #[derive(Default, Debug, TreeHash)]
        struct SigningData {
            object_root: [u8; 32],
            signing_domain: [u8; 32],
        }
    
        let signing_data = SigningData { object_root, signing_domain };
        signing_data.tree_hash_root().0
    }

    pub fn sign_message(&self, secret_key: &BlsSecretKey, msg: &[u8]) -> BlsSignature {
        let signature = secret_key.sign(msg, BLS_DST_SIG, &[]).to_bytes();
        BlsSignature::from_slice(&signature)
    }
}

impl EthgasBuilderService {
    pub async fn run(self) -> Result<(), Box<dyn Error>> {
        let client = Client::new();
        info!(bls_pubkey = ?self.bls_pubkey);
        if self.enable_registration {
            let mut exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/builder/register"))?;
            let mut res = client.post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.access_jwt))
                .header("content-type", "application/json")
                .query(&[("publicKey", self.bls_pubkey.to_string())])
                .send()
                .await?;
            match res.json::<APIBuilderRegisterResponse>().await {
                Ok(res_json_request) => {
                    info!(?res_json_request);

                    match res_json_request.data.message {
                        Some(api_builder_request_response_data_message) => {
                            let info = RegisteredInfo {
                                eoaAddress: api_builder_request_response_data_message.eoaAddress
                            };
                            let request = SignConsensusRequest::builder(self.bls_pubkey.into()).with_msg(&info);
                            info!("{:?}", request);

                            let domain = CommitBoostSigningService.compute_domain(self.chain, COMMIT_BOOST_DOMAIN);
                            let signing_root = CommitBoostSigningService.compute_signing_root(request.object_root, domain);
                            let signature = CommitBoostSigningService.sign_message(&self.bls_secret_key, &signing_root);
                            exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/builder/verify"))?;
                            res = client.post(exchange_api_url.to_string())
                                .header("Authorization", format!("Bearer {}", self.access_jwt))
                                .header("content-type", "application/json")
                                .query(&[("publicKey", self.bls_pubkey.to_string())])
                                .query(&[("signature", signature.to_string())])
                                .send()
                                .await?;

                            // println!("API Response as JSON: {}", res.json::<Value>().await?);
                            match res.json::<APIBuilderVerifyResponse>().await {
                                Ok(res_json_verify) => {
                                    info!(exchange_registration_response = ?res_json_verify);
                                    
                                    if res_json_verify.data.result == 0 {
                                        info!("successful builder registration");
                                    } else {
                                        error!("fail to register");
                                    }
                                },
                                Err(e) => error!("Failed to parse builder verification response: {}", e)
                            }
                        },
                        None => warn!("this BLS pubkey has been registered already"),
                    }
                },
                Err(err) => {
                    error!(?err, "fail to request for signing data");
                }
            }
        } else {
            let exchange_api_url = Url::parse(&format!("{}{}", self.exchange_api_base, "/api/v1/builder/deregister"))?;
            let res = client.post(exchange_api_url.to_string())
                .header("Authorization", format!("Bearer {}", self.access_jwt))
                .header("content-type", "application/json")
                .query(&[("publicKey", self.bls_pubkey.to_string())])
                .send()
                .await?;
            match res.json::<APIBuilderDeregisterResponse>().await {
                Ok(res_json) => {
                    info!(?res_json);
                    if res_json.success {
                        info!("successful de-registration!");
                    } else {
                        error!("failed to de-register");
                    }
                },
                Err(err) => {
                    error!(?err, "failed to call builder deregister API");
                }
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let subscriber = FmtSubscriber::builder().finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    dotenv().ok();

    info!(
        "Starting builder registration"
    );

    let chain_str = match env::var("CHAIN") {
        Ok(chain_str) => chain_str,
        Err(_) => {
            error!("Please set CHAIN environment variable");
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
            "CHAIN missing").into());
        }
    };
    let chain: Chain;
    if chain_str == "Holesky" {
        chain = Chain::Holesky;
    } else if chain_str == "Mainnet" {
        chain = Chain::Mainnet;
    } else if chain_str == "Hoodi" {
        chain = Chain::Hoodi;
    } else {
        return Err(std::io::Error::new(std::io::ErrorKind::Other,
            "unsupported chain").into());
    }
    info!(chain = chain_str);
    let enable_registration_str = match env::var("ENABLE_REGISTRATION") {
        Ok(value) => value,
        Err(_) => {
            error!("Please set ENABLE_REGISTRATION environment variable");
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
            "ENABLE_REGISTRATION missing").into());
        }
    };
    let enable_registration = match enable_registration_str.as_str() {
        "true" => true,
        "false" => false,
        _ => {
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                "ENABLE_REGISTRATION can only be true or false").into());
        }
    };
    let eoa_signing_key = match env::var("EOA_SIGNING_KEY") {
        Ok(eoa) => {
            B256::from_str(&eoa).map_err(|_| {
                error!("Invalid EOA_SIGNING_KEY format"); 
                std::io::Error::new(std::io::ErrorKind::InvalidData, "EOA_SIGNING_KEY format error")
            })?
        },
        Err(_) => {
            error!("Please set EOA_SIGNING_KEY environment variable");
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
            "EOA_SIGNING_KEY missing").into());
        }
    };
    let exchange_api_base = match env::var("EXCHANGE_API_BASE") {
        Ok(api) => api,
        Err(_) => {
            error!("Please set EXCHANGE_API_BASE environment variable");
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
            "EXCHANGE_API_BASE missing").into());
        }
    };
    let bls_secret_key_hex_str = match env::var("BLS_SECRET_KEY") {
        Ok(hex_str) => hex_str,
        Err(_) => {
            error!("Please set BLS_SECRET_KEY environment variable");
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
            "BLS_SECRET_KEY missing").into());
        }
    };
    let decoded = decode(bls_secret_key_hex_str.trim_start_matches("0x")).expect("Failed to decode hex string");
    let bls_secret_key_bytes: [u8; 32] = decoded.try_into().expect("Invalid length for [u8; 32]");
    let bls_secret_key = SecretKey::from_bytes(&bls_secret_key_bytes).unwrap();

    let bls_pubkey_hex_str = match env::var("BLS_PUBKEY") {
        Ok(hex_str) => hex_str,
        Err(_) => {
            error!("Please set BLS_PUBKEY environment variable");
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
            "BLS_PUBKEY missing").into());
        }
    };
    let decoded = decode(bls_pubkey_hex_str.trim_start_matches("0x")).expect("Failed to decode hex string");
    let bytes_array: [u8; 48] = decoded.try_into().expect("Invalid length for [u8; 48]");
    let bytes = FixedBytes::from(bytes_array);
    let bls_pubkey: BlsPublicKey = BlsPublicKey::from(bytes);


    

    let exchange_service = EthgasExchangeService {
        exchange_api_base,
        eoa_signing_key
    };
    let access_jwt = Retry::spawn(FixedInterval::from_millis(500).take(5), || async { 
        let service = EthgasExchangeService {
            exchange_api_base: exchange_service.exchange_api_base.clone(),
            eoa_signing_key: exchange_service.eoa_signing_key.clone(),
        };
        service.login().await.map_err(|err| {
            error!(?err, "Service failed");
            err
        })
    }).await?;

    if !access_jwt.is_empty() {
        let commit_service = EthgasBuilderService { 
            exchange_api_base: exchange_service.exchange_api_base.clone(), 
            access_jwt, 
            bls_secret_key, 
            bls_pubkey,
            chain,
            enable_registration
        };
        if let Err(err) = commit_service.run().await {
            error!(?err);
        }
    } else { 
        error!("JWT invalid") 
    }
    Ok(())
}
