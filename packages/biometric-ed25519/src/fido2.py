import base64
from fido2.client import Fido2Client
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialCreationOptions

class Fido2:
    def __init__(self):
        self.f2l = None

    async def init(self, rp_id, rp_name, timeout):
        self.f2l = Fido2Client(
            timeout=timeout,
            rp=PublicKeyCredentialRpEntity(
                id=rp_id,
                name=rp_name
            ),
            challenge_size=128,
            attestation="none",
            crypto_params=[
                {"type": "public-key", "alg": -8},
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257}
            ],
            authenticator_attachment="platform",
            authenticator_require_resident_key=True,
            authenticator_user_verification="preferred"
        )

    async def registration(self, username, display_name, user_id):
        registration_options = await self.f2l.register_begin(
            PublicKeyCredentialUserEntity(
                id=user_id,
                name=username,
                display_name=display_name
            )
        )

        challenge = base64.b64encode(registration_options.challenge).decode('utf-8')

        return {
            **registration_options.__dict__,
            "user": {
                "id": user_id,
                "name": username,
                "displayName": display_name
            },
            "status": "ok",
            "challenge": challenge
        }

    async def attestation(self, client_attestation_response, origin, challenge):
        attestation_expectations = {
            "challenge": challenge,
            "origin": origin,
            "factor": "either"
        }

        reg_result = await self.f2l.register_complete(
            client_attestation_response,
            attestation_expectations
        )

        return reg_result

    async def login(self):
        assertion_options = await self.f2l.authenticate_begin()

        challenge = base64.b64encode(assertion_options.challenge).decode('utf-8')

        return {
            **assertion_options.__dict__,
            "attestation": "direct",
            "challenge": challenge,
            "status": "ok"
        }