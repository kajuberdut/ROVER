# Dynamic Secret Injection with OpenBao

R.O.V.E.R.S requires sensitive credentials for vulnerability scans. These include private Git tokens, registry authentication, and scanner licenses. The scanning process relies on ephemeral Testcontainers. Docker Secrets fail here because they are immutable and bind at deploy-time. We need runtime dynamic injection. HashiCorp Vault is the industry standard but carries BSL licensing risks. OpenBao solves this issue.

OpenBao is an open-source fork of Vault. It maintains full API compatibility.

## Execution Flow

1. **Storage:** OpenBao runs as a dedicated container alongside Falcon, Authelia, and Postgres.
2. **Authentication:** Falcon authenticates against OpenBao using a machine-to-machine AppRole.
3. **Retrieval:** Falcon requests the required secret from the Key-Value (KV v2) store using the `hvac` Python client.
4. **Injection:** Falcon retrieves the plaintext secret into memory and passes it to the Testcontainer instance via environment variables.
5. **Cleanup:** The Testcontainer executes the scan and terminates. The ephemeral container and the secret are destroyed together.

## Dependencies

* OpenBao container image.
* `hvac` Python library.