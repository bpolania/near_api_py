import base64
from typing import List, Dict, Any
from ecdsa import NIST256p, SigningKey
from ecdsa.util import sigdecode_string
from crypto import PublicKey
from hashlib import sha256

def preformat_make_cred_req(make_cred_req: Dict[str, Any]) -> Dict[str, Any]:
    challenge = base64.b64decode(make_cred_req['challenge'])
    user_id = base64.b64decode(make_cred_req['user']['id'])

    formatted_req = {
        **make_cred_req,
        'challenge': challenge,
        'user': {
            **make_cred_req['user'],
            'id': user_id,
        }
    }

    if 'excludeCredentials' in make_cred_req:
        formatted_req['excludeCredentials'] = [
            {'id': base64.b64decode(e['id']), 'type': e['type']}
            for e in make_cred_req['excludeCredentials']
        ]

    return formatted_req

def get_64_byte_public_key_from_pem(public_key: PublicKey) -> bytes:
    prefix = '\n'
    public_key_base64 = public_key.to_string().split(prefix)
    return base64.b64decode(f"{public_key_base64[1]}{public_key_base64[2]}")[27:59]

def validate_username(name: str) -> str:
    if not name:
        raise ValueError('username is required')
    return name

def preformat_get_assert_req(get_assert: Dict[str, Any]) -> Dict[str, Any]:
    get_assert['challenge'] = base64.b64decode(get_assert['challenge'])

    for allow_cred in get_assert['allowCredentials']:
        allow_cred['id'] = base64.b64decode(allow_cred['id'])

    return get_assert

def public_key_credential_to_json(pub_key_cred: Any) -> Any:
    if isinstance(pub_key_cred, list):
        return [public_key_credential_to_json(i) for i in pub_key_cred]

    if isinstance(pub_key_cred, bytes):
        return base64.b64encode(pub_key_cred).decode('utf-8')

    if isinstance(pub_key_cred, dict):
        return {key: public_key_credential_to_json(value) for key, value in pub_key_cred.items()}

    return pub_key_cred

async def recover_public_key(r: int, s: int, message: bytes, recovery: int) -> List[bytes]:
    if recovery not in [0, 1]:
        raise ValueError('Invalid recovery parameter')

    sig_obj_q = (r, s, 0)
    sig_obj_p = (r, s, 1)
    hash_obj = sha256(message).digest()

    sk_q = SigningKey.from_public_key_recovery(sig_obj_q, hash_obj, NIST256p)
    sk_p = SigningKey.from_public_key_recovery(sig_obj_p, hash_obj, NIST256p)

    return [sk_q.get_verifying_key().to_string()[1:33], sk_p.get_verifying_key().to_string()[1:33]]

def uint8array_to_bigint(uint8array: bytes) -> int:
    return int.from_bytes(uint8array, 'big')

def convert_uint8array_to_bytes(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return obj
    return obj

def sanitize_create_key_response(res: Any) -> Any:
    if isinstance(res, dict) and (
        isinstance(res.get('rawId'), bytes) or
        isinstance(res.get('response', {}).get('clientDataJSON'), bytes) or
        isinstance(res.get('response', {}).get('attestationObject'), bytes)
    ):
        return {
            **res,
            'rawId': convert_uint8array_to_bytes(res['rawId']),
            'response': {
                **res['response'],
                'clientDataJSON': convert_uint8array_to_bytes(res['response']['clientDataJSON']),
                'attestationObject': convert_uint8array_to_bytes(res['response']['attestationObject']),
            }
        }
    return res

def sanitize_get_key_response(res: Any) -> Any:
    if isinstance(res, dict) and (
        isinstance(res.get('rawId'), bytes) or
        isinstance(res.get('response', {}).get('authenticatorData'), bytes) or
        isinstance(res.get('response', {}).get('clientDataJSON'), bytes) or
        isinstance(res.get('response', {}).get('signature'), bytes) or
        isinstance(res.get('response', {}).get('userHandle'), bytes)
    ):
        return {
            **res,
            'rawId': convert_uint8array_to_bytes(res['rawId']),
            'response': {
                **res['response'],
                'authenticatorData': convert_uint8array_to_bytes(res['response']['authenticatorData']),
                'clientDataJSON': convert_uint8array_to_bytes(res['response']['clientDataJSON']),
                'signature': convert_uint8array_to_bytes(res['response']['signature']),
                'userHandle': convert_uint8array_to_bytes(res['response']['userHandle']),
            }
        }
    return res