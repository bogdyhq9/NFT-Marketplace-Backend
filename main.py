from fastapi import FastAPI, Request
import httpx
from web3 import Web3
from fastapi.middleware.cors import CORSMiddleware
import json
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

from ca_fingerprint import CAFingerprint, UserVerificationSystem
from db_models import Fingerprint


app = FastAPI()
origins = [
    "http://localhost:5173"  # Your Vite/React frontend
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # You can use ["*"] to allow all for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

with open("abis/realEstate.json") as f:
    contract_abi = json.load(f)["abi"]

# Contract address
contract_address = "0x5529B4CEe217637e40B00b85c09c50f76AEDE94f"

# Connect to local Ganache or Infura
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))  # or Infura URL for testnet/mainnet

# Create contract instance
realEstateNFT= w3.eth.contract(address=contract_address, abi=contract_abi)


OWNER_PRIVATE_KEY = os.getenv("OWNER_PRIVATE_KEY")
OWNER_ADDRESS = w3.eth.account.from_key(OWNER_PRIVATE_KEY).address


verification_system = UserVerificationSystem(ca_width=256, fingerprint_size=32, iterations=50)

@app.post("/verify")
async def verify_user(request: Request):
    try:
        data = await request.json()
        print("hatz gion")
        # Extract user data
        wallet = data.get("wallet", "").strip()
        first_name = data.get("firstName", "").strip()
        last_name = data.get("lastName", "").strip()
        passport = data.get("passportNumber", "").strip()
        series = data.get("series", "").strip()

        # Validate required fields
        if not all([wallet, first_name, last_name, passport, series]):
            raise HTTPException(status_code=400, detail="Missing required fields")

        # Use the class method for verification
        result = verification_system.verify_user_data(first_name, last_name, passport, series)
        
        if not result["verified"]:
            return {
                "status": "verification_failed",
                "message": result["message"]
            }
        
        nonce = w3.eth.get_transaction_count(OWNER_ADDRESS)

        txn = realEstateNFT.functions.approveMinting(
            wallet
        ).build_transaction({
            'from': OWNER_ADDRESS,
            'nonce': nonce,
            'gas': 2000000,
            'gasPrice': w3.to_wei('20', 'gwei')
        })

        signed_txn = w3.eth.account.sign_transaction(txn, private_key=OWNER_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)

        
        return {
            "status": "approved_and_submitted",
            "txHash": tx_hash.hex(),
            "message": "User verified and minting approved"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/eth-usd")
async def get_eth_usd():
    url = "https://api.coingecko.com/api/v3/simple/price"
    params = {"ids": "ethereum", "vs_currencies": "usd"}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=params)
        data = response.json()
    print(data)    
    return {"eth_usd": data["ethereum"]["usd"]}


