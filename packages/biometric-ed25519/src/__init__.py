# packages/biometric-ed25519/__init__.py
import httpx

async def get_account_details(account_id, network_url):
    """
    Fetch details for a given account from the NEAR blockchain.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{network_url}/accounts/{account_id}")
        return response.json()