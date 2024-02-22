use auth::auth_header;
use chrono::{DateTime, Utc};
use reqwest::Client;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

const BASE_URL_TEST: &'static str = "https://demo-futures.kraken.com/derivatives";
const SEND_ORDER: &'static str = "/api/v3/sendorder";

#[derive(Serialize, Deserialize)]
struct ApiKey {
    pub public: String,
    pub secret: String,
}

impl ApiKey {
    pub fn new(public: String, secret: String) -> Self {
        Self { public, secret }
    }

    pub fn from_config() -> Result<Self, anyhow::Error> {
        let config_content = std::fs::read_to_string("config.toml")?;
        Ok(toml::from_str(&config_content)?)
    }
}

mod auth {
    use base64::{prelude::BASE64_STANDARD, Engine};
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};

use crate::ApiKey;

type HmacSha512 = Hmac<Sha512>;

const API_KEY: &str = "APIKey";
const NONCE_KEY: &str = "Nonce";
const AUTHENT_KEY: &str = "Authent";

pub fn auth_header<'a, T: std::fmt::Debug + Serialize>(
    api_key: &'a ApiKey,
    endpoint_path: &'a str,
    post_data: Option<T>,
) -> Result<HeaderMap, anyhow::Error> {
    let nonce = chrono::offset::Utc::now().timestamp_millis().to_string();
    let post_data_str =
        post_data.map_or(Ok("".to_string()), |d| serde_url_params::to_string(&d))?;
    println!("{post_data_str}");
    let authent = compute_authent(&api_key.secret, &post_data_str, &nonce, endpoint_path);
    let mut header = HeaderMap::new();
    header.insert(API_KEY, HeaderValue::from_str(&api_key.public)?);
    header.insert(NONCE_KEY, HeaderValue::from_str(&nonce)?);
    header.insert(AUTHENT_KEY, HeaderValue::from_str(&authent)?);
    Ok(header)
}

fn hmac(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut signer = HmacSha512::new_from_slice(secret).unwrap();
    signer.update(data);
    signer.finalize().into_bytes().to_vec()
}

fn compute_authent<'a>(
    api_secret: &'a str,
    post_data: &'a str,
    nonce: &'a str,
    endpoint_path: &'a str,
) -> String {
    let concat_str = post_data.to_owned() + nonce + endpoint_path;
    let challenge_hash = Sha256::digest(concat_str);
    let secret = BASE64_STANDARD
        .decode(api_secret)
        .expect("Should be able to base64 decode api secret");
    let digest = hmac(&secret, &challenge_hash);
    BASE64_STANDARD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_authent() {
        let authent = compute_authent("dGVzdA==", "query_url=test", "123456", "endpoint/test");
        assert_eq!(authent, "4VpYB/jFeE+rxr+F78O1jhn+kc2CP7w7G+ArO/HIh3H1auo1f6J56UcVt8F/an8nLZTNOYDcP1IaJw8rhtgQ1g==")
    }
}

}


#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateOrder {
    pub order_type: String,
    pub symbol: String,
    pub side: String,
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_ord_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_price: Option<Decimal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_price_offset_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_price_offset_value: Option<Decimal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reduce_only: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_price: Option<Decimal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trailing_stop_deviation_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trailing_stop_max_deviation: Option<Decimal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_signal: Option<String>,
}

#[tokio::main]
async fn main() {
    let client = Client::new();
    let api_keys = ApiKey::from_config().expect("Expects a config file in the root directory");
    let order = CreateOrder {
        cli_ord_id: None,
        order_type: "lmt".to_string(),
        side: "buy".to_string(),
        size: 1,
        symbol: "PI_XBTUSD".to_string(),
        limit_price: Some(Decimal::ONE),
        limit_price_offset_unit: None,
        limit_price_offset_value: None,
        process_before: None,
        reduce_only: Some("true".to_string()),
        stop_price: None,
        trailing_stop_deviation_unit: None,
        trailing_stop_max_deviation: None,
        trigger_signal: None,
    };

    insta::assert_json_snapshot!(order);
    let url = format!("{}{}", BASE_URL_TEST, SEND_ORDER);
    let resp = client
        .post(url)
        .headers(auth_header(&api_keys, SEND_ORDER, Some(&order)).unwrap())
        .json(&order)
        .send()
        .await.unwrap();
    insta::assert_display_snapshot!(resp.text().await.unwrap());
}
