from packages.accounts import create_account
from packages.crypto.src import sign_message
from packages.providers import send_rpc_request

from fastapi import FastAPI
from packages.accounts import get_account_details

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/account/{account_id}")
async def account_details(account_id: str):
    network_url = "https://rpc.mainnet.near.org"  # Example URL
    return await get_account_details(account_id, network_url)

# Additional routes for handling specific functionality can be added here
