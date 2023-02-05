mod model;

use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use aws_credential_types::provider::ProvideCredentials;
use aws_sig_auth::signer::{OperationSigningConfig, RequestConfig, SigV4Signer};
use aws_smithy_http::body::SdkBody;
use aws_types::{region::SigningRegion, SigningService};
use clap::Parser;
use http::{Method, Request};
use hyper::{Body, Client};
use hyper_rustls::HttpsConnectorBuilder;
use percent_encoding::utf8_percent_encode;

use crate::model::{
  GenerateAccessToken, GenerateAccessTokenResponse, GetCallerIdentityToken, Header, TokenExchange,
  TokenExchangeResponse,
};

/// Obtain a Google Cloud service account access token using AWS credentials, without revealing those credentials, via workload identity federation.
///
/// The AWS credentials used are selected using the default aws-sdk-rust credential provider chain, documented at [0].
///
/// If authentication is successful, the service account access token is printed to stdout and the program exits successfully.
///
/// If authentication is not successful, the program exits with a non-zero status and the error details are printed to stderr.
///
/// [0] https://github.com/awslabs/aws-sdk-rust/blob/main/README.md#getting-started-with-the-sdk
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
  /// Google Cloud identity pool provider URI (without scheme, beginning with //)
  #[clap(short, long)]
  identity_pool_provider: String,

  /// Google Cloud service account email address
  #[clap(short, long)]
  service_account: String,

  /// Print progress information to stderr while performing the authentication flow
  #[clap(short, long)]
  verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
  let args = Args::parse();

  let config = aws_config::load_from_env().await;
  let sts_config = aws_sdk_sts::Config::new(&config);

  let creds = config
    .credentials_provider()
    .context("no credentials provider")?
    .provide_credentials()
    .await?;

  let sts_endpoint = "sts.amazonaws.com";

  let mut req = Request::builder()
    .uri(format!(
      "https://{}/?Action=GetCallerIdentity&Version=2011-06-15",
      sts_endpoint
    ))
    .method(Method::POST)
    .header("host", sts_endpoint)
    .header("x-goog-cloud-target-resource", &args.identity_pool_provider)
    .body(SdkBody::empty())?;

  let mut op_signing_config = OperationSigningConfig::default_config();
  op_signing_config.expires_in = Some(Duration::from_secs(15 * 60));
  let req_config = RequestConfig {
    request_ts: SystemTime::now(),
    region: &SigningRegion::from_static("us-east-1"),
    service: &SigningService::from_static(sts_config.signing_service()),
    payload_override: None,
  };

  let _sig = SigV4Signer::new()
    .sign(&op_signing_config, &req_config, &creds, &mut req)
    .map_err(|_| anyhow!("failed to sign"))?;

  if args.verbose {
    eprintln!(
      "Generated signed AWS GetCallerIdentity request, exchanging for Google Cloud STS token..."
    );
  }

  let https_connector = HttpsConnectorBuilder::new()
    .with_native_roots()
    .https_only()
    .enable_http1()
    .enable_http2()
    .build();

  let https_client: Client<_, Body> = Client::builder().build(https_connector);

  let token = GetCallerIdentityToken {
    url: req.uri().to_string(),
    method: req.method().to_string(),
    headers: req
      .headers()
      .into_iter()
      .map(|(key, value)| {
        Ok(Header {
          key: key.to_string(),
          value: value.to_str()?.to_owned(),
        })
      })
      .collect::<Result<_>>()?,
  };
  let token = utf8_percent_encode(
    &serde_json::to_string(&token)?,
    percent_encoding::NON_ALPHANUMERIC,
  )
  .to_string();

  let scope = "https://www.googleapis.com/auth/cloud-platform";

  let token_exchange = TokenExchange {
    audience: &args.identity_pool_provider,
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
    scope,
    subject_token_type: "urn:ietf:params:aws:token-type:aws4_request",
    subject_token: &token,
  };

  let req = Request::builder()
    .uri("https://sts.googleapis.com/v1/token")
    .method("POST")
    .header("content-type", "application/json")
    .body(serde_json::to_vec(&token_exchange)?.into())?;

  let res = https_client.request(req).await?;

  if !res.status().is_success() {
    bail!(
      "Google Cloud refused to exchange token: HTTP {}",
      res.status()
    );
  }
  let body = hyper::body::to_bytes(res.into_body()).await?;
  let res: TokenExchangeResponse = serde_json::from_slice(&body)?;

  if args.verbose {
    eprintln!(
      "Successfully exchanged GetCallerIdentity request for STS token, generating access token..."
    );
  }

  let generate_access_token = GenerateAccessToken { scope: &[scope] };

  let req = Request::builder()
    .uri(format!(
      "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{}:generateAccessToken",
      utf8_percent_encode(&args.service_account, percent_encoding::NON_ALPHANUMERIC),
    ))
    .method("POST")
    .header("authorization", format!("Bearer {}", res.access_token))
    .header("content-type", "application/json")
    .body(serde_json::to_vec(&generate_access_token)?.into())?;
  let res = https_client.request(req).await?;

  if !res.status().is_success() {
    bail!(
      "Google Cloud refused to generate access token: HTTP {}",
      res.status()
    );
  }
  let body = hyper::body::to_bytes(res.into_body()).await?;
  let res: GenerateAccessTokenResponse = serde_json::from_slice(&body)?;

  if args.verbose {
    eprintln!("Federated authentication successful.");
  }

  println!("{}", res.access_token);

  Ok(())
}
