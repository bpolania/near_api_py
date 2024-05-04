import base64
from pywebauthn import webauthn
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder as asn1_decoder
from crypto import KeyPair
from utils import base_encode
from .utils import (
    validate_username,
    preformat_make_cred_req,
    get_64_byte_public_key_from_pem,
    preformat_get_assert_req,
    public_key_credential_to_json,
    recover_public_key,
    uint8array_to_bigint,
    sanitize_create_key_response,
    sanitize_get_key_response
)
from .fido2 import Fido2
from . import AssertionResponse

CHALLENGE_TIMEOUT_MS = 90 * 1000
RP_NAME = 'NEAR_API_JS_WEBAUTHN'

f2l = Fido2()

async def init(rp_id: str):
    await f2l.init(
        rp_id= rp_id, # location.hostname
        rp_name=RP_NAME,
        timeout=CHALLENGE_TIMEOUT_MS,
    )

class PasskeyProcessCanceled(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.name = 'PasskeyProcessCanceled'

async def get_public_key(credential: dict) -> str:
    
    # Extract public key bytes from the credential
    public_key_bytes = credential.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Convert the public key bytes to a string
    public_key_string = base64.urlsafe_b64encode(public_key_bytes).decode('utf-8')

    return public_key_string


async def create_key(navigator_credentials_create_response: str, origin: str) -> KeyPair:
    if not f2l.f2l:
        await init()

    sanitized_response = sanitize_create_key_response(navigator_credentials_create_response)
    challenge_make_cred = f2l.challenge_make_cred

    result = await f2l.attestation(
        client_attestation_response=sanitized_response,
        origin=origin,
        challenge=challenge_make_cred['challenge']
    )
    public_key_pem = result['authnrData']['credentialPublicKeyPem']
    public_key_bytes = get_64_byte_public_key_from_pem(public_key_pem)
    secret_key = hashes.Hash(hashes.SHA256()).update(public_key_bytes).finalize()
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(secret_key)
    return KeyPair.from_string(base_encode(secret_key + public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )))

async def get_keys(username: str, attestation_response: dict) -> tuple[KeyPair, KeyPair]:
    # Validate username and initialize if necessary
    clean_user_name = validate_username(username)
    if not f2l.f2l:
        await init()

    # Generate user_id
    user_id = base64.b64encode(clean_user_name.encode('utf-8')).decode('utf-8')

    # Create a WebAuthn Relying Party
    rp = webauthn.WebAuthnRP(f2l.rp_id, f2l.name)

    # Generate a new credential creation options
    challenge_make_cred, session_data = rp.start_credential_registration(
    username, user_id, require_resident_key=False)

    # Process the attestation response received from the client
    # You might want to validate and sanitize the data before using it
    # Here, assuming attestation_response contains the necessary data
    # (attestationObject and clientDataJSON) received from the client
    # You should perform proper validation and sanitization in your actual implementation
    # This step replaces the simulated client-side interaction
    # If the data is not trustworthy, consider verifying it with additional steps
    # such as cryptographic signatures or secure channels
    # Process the attestation response
    # assuming attestation_response contains the necessary data
    credential = rp.finish_registration(
        attestation_response,
        session_data,
        {"challenge": challenge_make_cred["challenge"]},
        rp.rp_id,
    )

    response = await get_public_key(credential)
    sanitized_response = sanitize_get_key_response(response)
    get_assertion_response: AssertionResponse = public_key_credential_to_json(sanitized_response)
    signature = base64.b64decode(get_assertion_response['response']['signature'])

    r_and_s, _ = asn1_decoder.decode(signature)
    client_data_json_hash = hashes.Hash(hashes.SHA256()).update(
        base64.b64decode(get_assertion_response['response']['clientDataJSON'])
    ).finalize()
    authenticator_data_json_hash = base64.b64decode(get_assertion_response['response']['authenticatorData'])
    authenticator_and_client_data_json_hash = authenticator_data_json_hash + client_data_json_hash

    r = uint8array_to_bigint(r_and_s[0])
    s = uint8array_to_bigint(r_and_s[1])
    correct_pks = await recover_public_key(r, s, authenticator_and_client_data_json_hash, 0)

    first_ed_secret = hashes.Hash(hashes.SHA256()).update(correct_pks[0]).finalize()
    first_ed_public = ed25519.Ed25519PublicKey.from_public_bytes(first_ed_secret)
    second_ed_secret = hashes.Hash(hashes.SHA256()).update(correct_pks[1]).finalize()
    second_ed_public = ed25519.Ed25519PublicKey.from_public_bytes(second_ed_secret)
    first_key_pair = KeyPair.from_string(base_encode(first_ed_secret + first_ed_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )))
    second_key_pair = KeyPair.from_string(base_encode(second_ed_secret + second_ed_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )))
    return first_key_pair, second_key_pair

async def is_passkey_available(publicKeyCredential) -> bool:
    return hasattr(publicKeyCredential, 'isUserVerifyingPlatformAuthenticatorAvailable')