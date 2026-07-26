"""tests/test_private_git.py: Unit tests for private Git repository URL authentication and token injection."""

import os
from unittest.mock import patch

from rover.vault import OpenBaoClient, get_authenticated_git_url, sanitize_git_url


class MockVaultClient(OpenBaoClient):
    def __init__(self) -> None:
        super().__init__("http://mock-vault:8200")
        self.secrets: dict[str, dict[str, str]] = {}

    def ensure_authenticated(self) -> bool:
        return True

    def write_secret(self, path: str, secret_data: dict[str, str]) -> bool:
        self.secrets[path] = secret_data
        return True

    def read_secret(self, path: str) -> dict[str, str] | None:
        return self.secrets.get(path)


def test_sanitize_git_url() -> None:
    raw_url = (
        "https://x-access-token:ghp_secret123456@github.com/my-org/private-repo.git"
    )
    sanitized = sanitize_git_url(raw_url)
    assert sanitized == "https://github.com/my-org/private-repo.git"
    assert "ghp_secret123456" not in sanitized

    public_url = "https://github.com/public/repo.git"
    assert sanitize_git_url(public_url) == public_url


def test_get_authenticated_git_url_with_vault() -> None:
    mock_vault = MockVaultClient()
    mock_vault.write_secret(
        "kv/data/rover/credentials/system/github.com",
        {"value": "ghp_system_pat_9999"},
    )

    url = "https://github.com/my-org/private-repo.git"
    auth_url = get_authenticated_git_url(url, vault_client=mock_vault)

    assert "x-access-token:ghp_system_pat_9999@github.com" in auth_url
    assert auth_url.endswith("/my-org/private-repo.git")


def test_get_authenticated_git_url_product_override() -> None:
    mock_vault = MockVaultClient()
    # System token
    mock_vault.write_secret(
        "kv/data/rover/credentials/system/git_token",
        {"value": "ghp_system_pat_000"},
    )
    # Product override token
    mock_vault.write_secret(
        "kv/data/rover/credentials/product/prod_abc/git_token",
        {"value": "ghp_product_pat_111"},
    )

    url = "https://github.com/my-org/private-repo.git"

    # With product context: uses product token
    auth_url_prod = get_authenticated_git_url(
        url, product_id="prod_abc", vault_client=mock_vault
    )
    assert "ghp_product_pat_111" in auth_url_prod

    # Without product context: uses system token
    auth_url_sys = get_authenticated_git_url(url, vault_client=mock_vault)
    assert "ghp_system_pat_000" in auth_url_sys


def test_get_authenticated_git_url_env_fallback() -> None:
    mock_vault = MockVaultClient()
    url = "https://github.com/my-org/private-repo.git"

    with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_env_token_777"}):
        auth_url = get_authenticated_git_url(url, vault_client=mock_vault)
        assert "ghp_env_token_777" in auth_url
