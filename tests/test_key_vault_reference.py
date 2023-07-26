from pydantic import BaseModel

from pydantic_azure_keyvault_secrets_types import KeyVaultReferenceStr


def test_key_vault_reference_str():
    class Model(BaseModel):
        key_vault: KeyVaultReferenceStr
        key_vault_version: KeyVaultReferenceStr
        alt_key_vault: KeyVaultReferenceStr
        alt_key_vault_version: KeyVaultReferenceStr

    # Initialize the model.
    f = Model(
        key_vault='@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/)',
        key_vault_version='@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/myversion)',
        alt_key_vault='@Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret)',
        alt_key_vault_version='@Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret;SecretVersion=myversion)'
    )

    # Assert correct types.
    assert f.key_vault.__class__.__name__ == 'KeyVaultField'
    assert f.key_vault_version.__class__.__name__ == 'KeyVaultField'
    assert f.alt_key_vault.__class__.__name__ == 'KeyVaultField'
    assert f.alt_key_vault_version.__class__.__name__ == 'KeyVaultField'

    # Assert reference are correct.
    assert f.key_vault.reference == '@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/)'
    assert f.key_vault_version.reference == '@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/myversion)'
    assert f.alt_key_vault.reference == '@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/)'
    assert f.alt_key_vault_version.reference == '@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/myversion)'

    # Assert reference_alternatively are correct.
    assert f.key_vault.reference_alternatively == '@Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret)'
    assert f.key_vault_version.reference_alternatively == '@Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret;SecretVersion=myversion)'
    assert f.alt_key_vault.reference_alternatively == '@Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret)'
    assert f.alt_key_vault_version.reference_alternatively == '@Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret;SecretVersion=myversion)'

    # Assert str and repr are correct.
    assert str(f.key_vault) == '@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/)'
    assert str(f.key_vault_version) == '@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/myversion)'
    assert str(f.alt_key_vault) == '@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/)'
    assert str(f.alt_key_vault_version) == '@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/myversion)'
    assert repr(f.key_vault) == "KeyVaultField('@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/)')"
    assert repr(f.key_vault_version) == "KeyVaultField('@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/myversion)')"
    assert len(f.key_vault) == 80
    assert len(f.key_vault_version) == 89
    assert len(f.alt_key_vault) == 80
    assert len(f.alt_key_vault_version) == 89
