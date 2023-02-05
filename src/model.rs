use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct Header {
  pub key: String,
  pub value: String,
}

#[derive(Serialize)]
pub struct GetCallerIdentityToken {
  pub url: String,
  pub method: String,
  pub headers: Vec<Header>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenExchange<'a> {
  pub audience: &'a str,
  pub grant_type: &'a str,
  pub requested_token_type: &'a str,
  pub scope: &'a str,
  pub subject_token_type: &'a str,
  pub subject_token: &'a str,
}

#[derive(Deserialize)]
pub struct TokenExchangeResponse {
  pub access_token: String,
}

#[derive(Serialize)]
pub struct GenerateAccessToken<'a> {
  pub scope: &'a [&'a str],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateAccessTokenResponse {
  pub access_token: String,
}
