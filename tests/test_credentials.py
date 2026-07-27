"""tests/test_credentials.py: Unit tests for Credential Vault and OpenBao integration."""

import pytest
from sqlalchemy import create_engine

from rover import db
from rover.db import connection, schema
from rover.db.credentials import (
    MASKED_SECRET_VALUE,
    add_credential,
    delete_credential,
    get_credentials,
    get_unmasked_secret,
)
from rover.vault import OpenBaoClient


@pytest.fixture(autouse=True)
def sqlite_test_db() -> None:
    test_engine = create_engine("sqlite:///:memory:")
    connection.engine = test_engine
    schema.products.create(test_engine)
    schema.credentials.create(test_engine)


class MockVaultClient(OpenBaoClient):
    def __init__(self) -> None:
        super().__init__("http://mock-vault:8200")
        self.store: dict[str, dict] = {}

    def ensure_authenticated(self) -> bool:
        return True

    def write_secret(self, path: str, secret_data: dict) -> bool:
        self.store[path] = secret_data
        return True

    def read_secret(self, path: str) -> dict | None:
        return self.store.get(path)

    def delete_secret(self, path: str) -> bool:
        self.store.pop(path, None)
        return True


def test_credential_vault_crud_operations() -> None:
    mock_vault = MockVaultClient()

    # 1. Add System-wide Git token
    cred = add_credential(
        name="test-github-pat",
        credential_type="git_token",
        scope="system",
        secret_value="ghp_secret_1234567890",  # noqa: S106
        description="System Github PAT",
        vault_client=mock_vault,
    )

    assert cred["name"] == "test-github-pat"
    assert cred["scope"] == "system"
    assert cred["masked_value"] == MASKED_SECRET_VALUE

    # 2. Add Product-specific Registry token
    prod_id = db.add_product("Vault Test Product", "Vault Product Desc")
    prod_cred = add_credential(
        name="dockerhub-pass",
        credential_type="registry_token",
        scope="product",
        secret_value="secret_reg_pass_999",  # noqa: S106
        product_id=prod_id,
        description="Product Registry Pass",
        vault_client=mock_vault,
    )

    assert prod_cred["product_id"] == prod_id
    assert prod_cred["masked_value"] == MASKED_SECRET_VALUE

    # 3. Retrieve unmasked secret values from Vault
    unmasked_sys = get_unmasked_secret(
        "test-github-pat", scope="system", vault_client=mock_vault
    )
    assert unmasked_sys == "ghp_secret_1234567890"

    unmasked_prod = get_unmasked_secret(
        "dockerhub-pass", scope="product", product_id=prod_id, vault_client=mock_vault
    )
    assert unmasked_prod == "secret_reg_pass_999"

    # 4. List credentials
    creds = get_credentials()
    assert len(creds) >= 2
    for c in creds:
        assert c["masked_value"] == MASKED_SECRET_VALUE

    # 5. Delete credential
    success = delete_credential(cred["id"], vault_client=mock_vault)
    assert success is True
    assert (
        get_unmasked_secret("test-github-pat", scope="system", vault_client=mock_vault)
        is None
    )


def test_get_unmasked_secret_by_type_custom_name() -> None:
    mock_vault = MockVaultClient()
    add_credential(
        name="winnow token",
        credential_type="git_token",
        scope="system",
        secret_value="ghp_winnow_secret_999",  # noqa: S106
        description="GitHub token for winnow repo",
        vault_client=mock_vault,
    )

    unmasked = db.get_unmasked_secret_by_type(
        credential_type="git_token",
        hostname="github.com",
        vault_client=mock_vault,
    )
    assert unmasked == "ghp_winnow_secret_999"
