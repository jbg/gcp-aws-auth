# gcp-aws-auth: authenticate to a Google Cloud service account using an AWS role

**gcp-aws-auth** obtains a Google Cloud service account access token using AWS credentials, without revealing those credentials, via workload identity federation.

Example using Terraform to create the necessary cloud resources:

```hcl
data "aws_caller_identity" "current" {}

data "google_project" "current" {}

resource "google_iam_workload_identity_pool" "example" {
  provider = google-beta

  workload_identity_pool_id = "my-example"
}

resource "google_iam_workload_identity_pool_provider" "example_aws" {
  provider = google-beta

  workload_identity_pool_id          = google_iam_workload_identity_pool.example.workload_identity_pool_id
  workload_identity_pool_provider_id = "example-aws"

  attribute_mapping = {
    "google.subject"     = "assertion.arn"
    "attribute.aws_role" = "assertion.arn.contains('assumed-role') ? assertion.arn.extract('{account_arn}assumed-role/') + 'assumed-role/' + assertion.arn.extract('assumed-role/{role_name}/') : assertion.arn"
  }

  aws {
    account_id = data.aws_caller_identity.current.account_id
  }
}

data "aws_iam_policy_document" "example_assume_role" {
  # Add policy statements here to permit assuming this role.
}

resource "aws_iam_role" "example" {
  name               = "example"
  assume_role_policy = data.aws_iam_policy_document.example_assume_role.json
}

resource "google_service_account" "example" {
  account_id = "example-service-account"
}

locals {
  assumed_role_arn = "arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${aws_iam_role.example.name}"
}

data "google_iam_policy" "example" {
  binding {
    role    = "roles/iam.workloadIdentityUser"
    members = ["principalSet://iam.googleapis.com/projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.example.workload_identity_pool_id}/attribute.aws_role/${local.assumed_role_arn}"]
  }
}

resource "google_service_account_iam_policy" "example" {
  service_account_id = google_service_account.example.name
  policy_data        = data.google_iam_policy.example.policy_data
}
```

With the above configuration, after assuming the `example` AWS role, you can run **gcp-aws-auth** to obtain an access token for the `example` Google Cloud service account:

```console
$ google_cloud_project_number=1234567890
$ google_cloud_project_id=example-project
$ identity_pool_id=example
$ identity_pool_provider_id=example-aws
$ service_account_id=example-service-account

$ access_token_file=access-token.tmp

$ gcp-aws-auth --identity-pool-provider="//iam.googleapis.com/projects/${google_cloud_project_number}/locations/global/workloadIdentityPools/${identity_pool_id}/providers/${identity_pool_provider_id}" --service-account="${service_account_id}@${google_cloud_project_id}.iam.gserviceaccount.com" --verbose > "$access_token_file"
Generated signed AWS GetCallerIdentity request, exchanging for Google Cloud STS token...
Successfully exchanged GetCallerIdentity request for STS token, generating access token...
Federated authentication successful.

$ gcloud config set auth/access_token_file "$access_token_file"
```

## License

`gcp-aws-auth` is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Any kinds of contributions are welcome as a pull request.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in these crates by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
