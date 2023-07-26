import re
from functools import lru_cache
from typing import (
    Any,
    Callable,
)

from pydantic import (
    GetJsonSchemaHandler,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import PydanticCustomError
from pydantic_core import core_schema
from typing_extensions import Annotated

try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient, KeyVaultSecret
except ModuleNotFoundError:  # pragma: no cover
    raise RuntimeError(
        '`AzureKeyVault` requires "azure-keyvault-secrets azure-identity" to be installed. You can install it with "pip install azure-keyvault-secrets azure-identity"'
    )


class KeyVaultField:
    """
    This is meant to represent a type from a third-party library that wasn't designed with Pydantic
    integration in mind, and so doesn't have a `pydantic_core.CoreSchema` or anything.
    """

    vault_name: str
    secret_name: str
    secret_version: str | None

    def __init__(self, vault_name: str, secret_name: str, secret_version: str | None):
        self.vault_name = vault_name
        self.secret_name = secret_name
        self.secret_version = secret_version if secret_version else None

    @property
    def secret_uri(self):
        return f"https://{self.vault_name}.vault.azure.net/secrets/{self.secret_name}/{self.secret_version if self.secret_version else ''}"

    @property
    def reference(self):
        return f"@Microsoft.KeyVault(SecretUri={self.secret_uri})"

    @property
    def reference_alternatively(self):
        if self.secret_version:
            return f"@Microsoft.KeyVault(VaultName={self.vault_name};SecretName={self.secret_name};SecretVersion={self.secret_version})"
        else:
            return f"@Microsoft.KeyVault(VaultName={self.vault_name};SecretName={self.secret_name})"

    @lru_cache
    def get_secret_client(self):
        credential = DefaultAzureCredential()
        vault_url = f"https://{self.vault_name}.vault.azure.net"
        return SecretClient(vault_url=vault_url, credential=credential)

    @lru_cache
    def get_secret_value(self) -> str | None:
        key_vault_secret: KeyVaultSecret = \
            self.get_secret_client().get_secret(name=self.secret_name, version=self.secret_version)
        return key_vault_secret.value

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, self.__class__) and self.reference == other.reference

    def __hash__(self) -> int:
        return hash(self.reference)

    def __len__(self) -> int:
        return len(self.reference)

    def __str__(self) -> str:
        return str(self.reference)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self.reference!r})'


regex_secret_uri_reference = r'\@Microsoft\.KeyVault\(SecretUri\=(.*)\)'
regex_vault_name = r'\@Microsoft\.KeyVault\(VaultName\=(.*);\s*SecretName\=(.*)\)'
regex_vault_name_version = r'\@Microsoft\.KeyVault\(VaultName\=(.*);\s*SecretName\=(.*);\s*SecretVersion\=(.*)\)'
regex_secret_uri = r'https\:\/\/(.*)\.vault\.azure\.net\/secrets\/(.*|\/)\/(.*)'

KeyVaultFieldException = PydanticCustomError(
    'invalid_key_vault_field',
    'Input is not valid KeyVaultField',
)


def secret_uri_to_key_vault_reference(value: str):
    m = re.fullmatch(regex_secret_uri, value)
    if m:
        reference = m.groups()
        return KeyVaultField(vault_name=reference[0], secret_name=reference[1], secret_version=reference[2])
    raise KeyVaultFieldException


def vault_name_to_key_vault_reference(vault_name: str, secret_name: str):
    return KeyVaultField(vault_name=vault_name, secret_name=secret_name, secret_version=None)


def vault_name_include_version_to_key_vault_reference(vault_name: str, secret_name: str, secret_version: str | None):
    return KeyVaultField(vault_name=vault_name, secret_name=secret_name, secret_version=secret_version)


def parse_str(value):
    m = re.fullmatch(regex_vault_name_version, value)
    if m:
        return vault_name_include_version_to_key_vault_reference(*m.groups())

    m = re.fullmatch(regex_vault_name, value)
    if m:
        return vault_name_to_key_vault_reference(*m.groups())

    m = re.fullmatch(regex_secret_uri_reference, value)
    if m:
        return secret_uri_to_key_vault_reference(*m.groups())

    raise KeyVaultFieldException


class _KeyVaultFieldAnnotation:
    @classmethod
    def __get_pydantic_core_schema__(
            cls,
            _source_type: Any,
            _handler: Callable[[Any], core_schema.CoreSchema],
    ) -> core_schema.CoreSchema:
        """
        We return a pydantic_core.CoreSchema that behaves in the following ways:

        * ints will be parsed as `ThirdPartyType` instances with the int as the x attribute
        * `ThirdPartyType` instances will be parsed as `ThirdPartyType` instances without any changes
        * Nothing else will pass validation
        * Serialization will always return just an int
        """

        def validate_from_srt(value: str) -> KeyVaultField:
            return parse_str(value)

        from_str_schema = core_schema.chain_schema(
            [
                core_schema.str_schema(),
                core_schema.no_info_plain_validator_function(validate_from_srt),
            ]
        )

        return core_schema.json_or_python_schema(
            json_schema=from_str_schema,
            python_schema=core_schema.union_schema(
                [
                    # check if it's an instance first before doing any further work
                    core_schema.is_instance_schema(KeyVaultField),
                    from_str_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda instance: str(instance)
            ),
        )

    @classmethod
    def __get_pydantic_json_schema__(
            cls, _core_schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        # Use the same schema that would be used for `str`
        return handler(core_schema.str_schema())


KeyVaultReferenceStr = Annotated[
    KeyVaultField, _KeyVaultFieldAnnotation
]
