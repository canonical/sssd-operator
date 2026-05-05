# Terraform module for sssd

This is a Terraform module facilitating the deployment of the sssd charm using
the [Juju Terraform provider](https://github.com/juju/terraform-provider-juju).
For more information, refer to the
[documentation](https://registry.terraform.io/providers/juju/juju/latest/docs)
for the Juju Terraform provider.

## Requirements

- Terraform >= 1.0
- Juju Terraform provider >= 1.0.0, < 2.0.0
- An existing Juju model

## API

### Inputs

| Name          | Type        | Description                                                        | Default         | Required |
|---------------|-------------|--------------------------------------------------------------------|-----------------|:--------:|
| `app_name`    | string      | The Juju application name                                          | `"sssd"`        |          |
| `base`        | string      | Operating system base (for example, `ubuntu@24.04`)                | `null`          |          |
| `channel`     | string      | Charm channel to deploy from                                       | `"latest/beta"` |          |
| `config`      | map(string) | Map of charm configuration options                                 | `{}`            |          |
| `model_uuid`  | string      | UUID of the Juju model to deploy the charm into                    |                 |    Y     |
| `revision`    | number      | Charm revision to deploy. Null deploys the latest on given channel | `null`          |          |

### Outputs

| Name          | Description                              |
|---------------|------------------------------------------|
| `application` | The deployed `juju_application` resource |
| `requires`    | Map of `requires` endpoint names         |

The `requires` output exposes the following endpoint names:

| Key               | Endpoint name     |
|-------------------|-------------------|
| `juju-info`       | `juju-info`       |
| `ldap`            | `ldap`            |
| `receive-ca-cert` | `receive-ca-cert` |

## Usage

Ensure that Terraform is aware of the Juju model dependency of the charm module.

```hcl
module "sssd" {
  source     = "git::https://github.com/canonical/sssd-operator//terraform"
  model_uuid = juju_model.my_model.uuid
}
```

To deploy this module with its required dependency, you can run the following
command:

```shell
terraform apply -var="model_uuid=<MODEL_UUID>" -auto-approve
```
