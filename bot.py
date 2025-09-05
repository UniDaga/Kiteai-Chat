import os
import time
import json
import asyncio
import random
import requests
from requests_toolbelt import sessions
from web3 import Web3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fake_useragent import UserAgent
import aiofiles
from datetime import datetime, timedelta
import logging
from logging import info, error
import sys


class Colors:
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    WHITE = '\033[37m'
    CYAN = '\033[36m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


logging.basicConfig(level=logging.INFO, format='%(message)s')
class Logger:
    @staticmethod
    def info(msg): info(f"{Colors.GREEN}[✓] {msg}{Colors.RESET}")
    @staticmethod
    def wallet(msg): info(f"{Colors.YELLOW}[➤] {msg}{Colors.RESET}")
    @staticmethod
    def error(msg): error(f"{Colors.RED}[✗] {msg}{Colors.RESET}")
    @staticmethod
    def success(msg): info(f"{Colors.GREEN}[] {msg}{Colors.RESET}")
    @staticmethod
    def loading(msg): info(f"{Colors.CYAN}[⟳] {msg}{Colors.RESET}")
    @staticmethod
    def step(msg): info(f"{Colors.WHITE}[➤] {msg}{Colors.RESET}")
    @staticmethod
    def banner():
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("---------------------------------------------")
        print("             KiteAI Auto Bot  1.0 ")
        print(f"---------------------------------------------{Colors.RESET}\n")
    @staticmethod
    def agent(msg): info(f"{Colors.WHITE}{msg}{Colors.RESET}")

logger = Logger()


AGENTS = [
    {"name": "Professor", "service_id": "deployment_KNmBm5VWg1HtB6AHXxX0vcyX"},
    {"name": "Crypto Buddy", "service_id": "deployment_xaYs98q4iraSThDSPcuPxZko"},
    {"name": "Sherlock", "service_id": "deployment_15kFpEbiREAocsWpSxbGATAr"},
]


ua = UserAgent()
BASE_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
    "Origin": "https://testnet.gokite.ai",
    "Referer": "https://testnet.gokite.ai/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "User-Agent": ua.random,
    "Content-Type": "application/json",
}

async def load_proxies():
    try:
        async with aiofiles.open("proxy.txt", "r") as f:
            content = await f.read()
        proxies = [line.strip() for line in content.split("\n") if line.strip() and not line.startswith("#")]
        if not proxies:
            logger.info("No proxies found in proxy.txt, will use direct connection")
            return None
        logger.info(f"Loaded {len(proxies)} proxies from proxy.txt")
        return proxies
    except FileNotFoundError:
        logger.info("proxy.txt not found or empty, will use direct connection")
        return None

def get_cycled_proxy(proxies, index):
    if not proxies or not len(proxies):
        return None
    return proxies[index % len(proxies)]

def create_session(proxy):
    session = sessions.BaseUrlSession(base_url="")
    if proxy:
        proxy_url = proxy if proxy.startswith("http") else f"http://{proxy}"
        session.proxies = {"http": proxy_url, "https": proxy_url}
    return session

async def load_prompts():
    try:
        async with aiofiles.open("prompt.txt", "r") as f:
            content = await f.read()
        lines = [line.strip() for line in content.split("\n")]
        prompt_generators = {}
        current_agent = None

        for line in lines:
            if line.startswith("[") and line.endswith("]"):
                current_agent = line[1:-1].strip()
                prompt_generators[current_agent] = []
            elif line and not line.startswith("#") and current_agent:
                prompt_generators[current_agent].append(line)

        for agent in AGENTS:
            if not prompt_generators.get(agent["name"]) or not prompt_generators[agent["name"]]:
                logger.error(f"No prompts found for agent {agent['name']} in prompt.txt")
                sys.exit(1)

        return prompt_generators
    except FileNotFoundError:
        logger.error("Failed to load prompt.txt: File not found")
        sys.exit(1)

def get_random_prompt(agent_name, prompt_generators):
    prompts = prompt_generators.get(agent_name, [])
    return random.choice(prompts) if prompts else None

def encrypt_address(address):
    try:
        key_hex = "6a1c35292b7c5b769ff47d89a17e7bc4f0adfe1b462981d28e0e9f7ff20b8f8a"
        key = bytes.fromhex(key_hex)
        iv = os.urandom(12)
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(iv, address.encode(), None)
        auth_tag = encrypted[-16:]  
        ciphertext = encrypted[:-16]
        result = iv + ciphertext + auth_tag
        return result.hex()
    except Exception as e:
        logger.error(f"Auth token generation failed for {address}: {str(e)}")
        return None

def extract_cookies(headers):
    try:
        raw_cookies = headers.get("set-cookie", [])
        skip_keys = ["expires", "path", "domain", "samesite", "secure", "httponly", "max-age"]
        cookies_dict = {}
        for cookie_str in raw_cookies:
            parts = cookie_str.split(";")
            for part in parts:
                cookie = part.strip()
                if "=" in cookie:
                    name, value = cookie.split("=", 1)
                    if name.lower() not in skip_keys:
                        cookies_dict[name] = value
        return "; ".join(f"{k}={v}" for k, v in cookies_dict.items()) or None
    except Exception:
        return None

def get_wallet(private_key):
    try:
        w3 = Web3()
        wallet = w3.eth.account.from_key(private_key)
        logger.info(f"Wallet created: {wallet.address}")
        return wallet
    except Exception as e:
        logger.error(f"Invalid private key: {str(e)}")
        return None

async def login(wallet, neo_session=None, refresh_token=None, max_retries=3, session=None):
    url = "https://neo.prod.gokite.ai/v2/signin"
    for attempt in range(1, max_retries + 1):
        try:
            logger.loading(f"Logging in to {wallet.address} (Attempt {attempt}/{max_retries})")
            auth_token = encrypt_address(wallet.address)
            if not auth_token:
                return None

            headers = {**BASE_HEADERS, "Authorization": auth_token}
            if neo_session or refresh_token:
                cookies = []
                if neo_session:
                    cookies.append(f"neo_session={neo_session}")
                if refresh_token:
                    cookies.append(f"refresh_token={refresh_token}")
                headers["Cookie"] = "; ".join(cookies)

            body = {"eoa": wallet.address}
            response = session.post(url, json=body, headers=headers)
            response.raise_for_status()
            data = response.json()

            if data.get("error"):
                logger.error(f"Login failed for {wallet.address}: {data['error']}")
                return None

            access_token = data["data"]["access_token"]
            aa_address = data["data"]["aa_address"]
            displayed_name = data["data"]["displayed_name"]
            avatar_url = data["data"]["avatar_url"]
            cookie_header = extract_cookies(response.headers)

            if not aa_address:
                profile = await get_user_profile(access_token, session)
                aa_address = profile["profile"]["smart_account_address"] if profile else None
                if not aa_address:
                    logger.error(f"No aa_address found for {wallet.address}")
                    return None

            logger.success(f"Login successful for {wallet.address}")
            return {
                "access_token": access_token,
                "aa_address": aa_address,
                "displayed_name": displayed_name,
                "avatar_url": avatar_url,
                "cookie_header": cookie_header,
            }
        except Exception as e:
            error_message = str(e)
            if attempt == max_retries:
                logger.error(f"Login failed for {wallet.address} after {max_retries} attempts: {error_message}")
                return None
            await asyncio.sleep(2)

async def get_user_profile(access_token, session):
    try:
        headers = {**BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
        response = session.get("https://ozone-point-system.prod.gokite.ai/me", headers=headers)
        response.raise_for_status()
        data = response.json()
        if data.get("error"):
            logger.error(f"Failed to fetch profile: {data['error']}")
            return None
        return data["data"]
    except Exception as e:
        logger.error(f"Profile fetch error: {str(e)}")
        return None

async def interact_with_agent(access_token, aa_address, cookie_header, agent, prompt, interaction_count, session, max_retries=3):
    for attempt in range(1, max_retries + 1):
        try:
            if not aa_address:
                logger.error(f"Cannot interact with {agent['name']}: No aa_address")
                return None

            logger.step(f"Interaction {interaction_count} - Prompts: {prompt}")

            inference_headers = {**BASE_HEADERS, "Authorization": f"Bearer {access_token}", "Accept": "text/event-stream"}
            if cookie_header:
                inference_headers["Cookie"] = cookie_header

            inference_response = session.post(
                "https://ozone-point-system.prod.gokite.ai/agent/inference",
                json={
                    "service_id": agent["service_id"],
                    "subnet": "kite_ai_labs",
                    "stream": True,
                    "body": {"stream": True, "message": prompt},
                },
                headers=inference_headers,
            )
            inference_response.raise_for_status()

            output = ""
            lines = inference_response.text.split("\n")
            for line in lines:
                if line.startswith("data: ") and line != "data: [DONE]":
                    try:
                        data = json.loads(line[6:])
                        if data.get("choices", []) and data["choices"][0].get("delta", {}).get("content"):
                            output += data["choices"][0]["delta"]["content"]
                            if len(output) > 100:
                                output = output[:100] + "..."
                                break
                    except json.JSONDecodeError:
                        pass

            receipt_headers = {**BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
            if cookie_header:
                receipt_headers["Cookie"] = cookie_header

            receipt_response = session.post(
                "https://neo.prod.gokite.ai/v2/submit_receipt",
                json={
                    "address": aa_address,
                    "service_id": agent["service_id"],
                    "input": [{"type": "text/plain", "value": prompt}],
                    "output": [{"type": "text/plain", "value": output or "No response"}],
                },
                headers=receipt_headers,
            )
            receipt_response.raise_for_status()
            receipt_data = receipt_response.json()

            if receipt_data.get("error"):
                logger.error(f"Receipt submission failed for {agent['name']}: {receipt_data['error']}")
                return None

            receipt_id = receipt_data["data"]["id"]
            logger.step(f"Interaction {interaction_count} - Receipt submitted, ID: {receipt_id}")

            max_attempts = 10
            for attempt in range(max_attempts):
                status_response = session.get(
                    f"https://neo.prod.gokite.ai/v1/inference?id={receipt_id}",
                    headers={**BASE_HEADERS, "Authorization": f"Bearer {access_token}"},
                )
                status_response.raise_for_status()
                status_data = status_response.json()

                if status_data["data"].get("processed_at") and status_data["data"].get("tx_hash"):
                    logger.step(f"Interaction {interaction_count} - Inference processed, tx_hash: {status_data['data']['tx_hash']}")
                    return status_data["data"]
                await asyncio.sleep(2)

            logger.error(f"Inference status not completed after {max_attempts} attempts")
            return None
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                wait_time = 2 ** attempt  
                logger.error(f"429 Too Many Requests for {agent['name']} (Attempt {attempt}/{max_retries}), retrying in {wait_time}s")
                await asyncio.sleep(wait_time)
                if attempt == max_retries:
                    logger.error(f"Max retries reached for {agent['name']}: {str(e)}")
                    return None
            else:
                logger.error(f"Error interacting with {agent['name']}: {str(e)}")
                return None
        except Exception as e:
            logger.error(f"Error interacting with {agent['name']}: {str(e)}")
            return None
        finally:
            
            await asyncio.sleep(3)

def get_next_run_time():
    now = datetime.now()
    next_run = now + timedelta(hours=24)
    next_run = next_run.replace(minute=0, second=0, microsecond=0)
    return next_run

async def display_countdown(next_run_time, interaction_count, proxies):
    while True:
        now = datetime.now()
        time_left = (next_run_time - now).total_seconds()
        if time_left <= 0:
            logger.info("Starting new run...")
            await daily_run(interaction_count, proxies)
            return
        hours, rem = divmod(time_left, 3600)
        minutes, seconds = divmod(rem, 60)
        print(f"\r{Colors.CYAN}[⏰] Next run in: {int(hours)}h {int(minutes)}m {int(seconds)}s{Colors.RESET}", end="")
        await asyncio.sleep(1)

async def process_wallet(wallet_data, interaction_count, prompt_generators, proxies, wallet_index):
    try:
        proxy = get_cycled_proxy(proxies, wallet_index)
        session = create_session(proxy)
        if proxy:
            logger.info(f"Using proxy for wallet {wallet_index + 1}: {proxy}")
        else:
            logger.info(f"Using direct connection (no proxy) for wallet {wallet_index + 1}")

        wallet = get_wallet(wallet_data["private_key"])
        if not wallet:
            return None

        logger.wallet(f"Processing wallet: {wallet.address}")
        login_data = await login(
            wallet, wallet_data.get("neo_session"), wallet_data.get("refresh_token"), 3, session
        )
        if not login_data:
            return None

        access_token = login_data["access_token"]
        aa_address = login_data["aa_address"]
        displayed_name = login_data["displayed_name"]
        cookie_header = login_data["cookie_header"]

        if not aa_address:
            return None

        profile = await get_user_profile(access_token, session)
        if not profile:
            return None

        logger.info(f"User: {profile['profile'].get('displayed_name', displayed_name or 'Unknown')}")
        logger.info(f"EOA Address: {profile['profile'].get('eoa_address', wallet.address)}")
        logger.info(f"Smart Account: {profile['profile'].get('smart_account_address', aa_address)}")
        logger.info(f"Total XP Points: {profile['profile'].get('total_xp_points', 0)}")
        logger.info(f"Referral Code: {profile['profile'].get('referral_code', 'None')}")
        logger.info(f"Badges Minted: {len(profile['profile'].get('badges_minted', []))}")
        logger.info(f"Twitter Connected: {'Yes' if profile['social_accounts'].get('twitter', {}).get('id') else 'No'}")

        for agent in AGENTS:
            agent_header = (
                "\n----- PROFESSOR -----" if agent["name"] == "Professor" else
                "----- CRYPTO BUDDY -----" if agent["name"] == "Crypto Buddy" else
                "----- SHERLOCK -----"
            )
            logger.agent(agent_header)

            for i in range(interaction_count):
                prompt = get_random_prompt(agent["name"], prompt_generators)
                await interact_with_agent(access_token, aa_address, cookie_header, agent, prompt, i + 1, session)
                await asyncio.sleep(5)  
            logger.agent("\n")

        return {"success": True, "address": wallet.address}
    except Exception as e:
        logger.error(f"Error processing wallet {wallet_data['private_key']}: {str(e)}")
        return {"success": False, "address": wallet_data["private_key"] and Web3().eth.account.from_key(wallet_data["private_key"]).address or "Unknown"}
    finally:
        
        await asyncio.sleep(2)

async def daily_run(interaction_count, proxies):
    logger.banner()
    prompt_generators = await load_prompts()

    try:
        async with aiofiles.open("accounts.txt", "r") as f:
            content = await f.read()
        wallets = []
        for line in content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(",")
                private_key = parts[0].strip()
                neo_session = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
                refresh_token = parts[2].strip() if len(parts) > 2 and parts[2].strip() else None
                wallets.append({"private_key": private_key, "neo_session": neo_session, "refresh_token": refresh_token})
    except FileNotFoundError:
        logger.error("No valid private keys found in accounts.txt")
        return

    if not wallets:
        logger.error("No valid private keys found in accounts.txt")
        return

    if interaction_count is None:
        try:
            interaction_count = int(input("Enter the number of interactions per agent: "))
            if interaction_count < 1 or interaction_count > 99999:
                logger.error("Invalid input. Please enter a number between 1 and 99999.")
                sys.exit(1)
        except ValueError:
            logger.error("Invalid input. Please enter a number between 1 and 99999.")
            sys.exit(1)

    
    semaphore = asyncio.Semaphore(10)

    async def process_wallet_limited(wallet, index):
        async with semaphore:
            return await process_wallet(wallet, interaction_count, prompt_generators, proxies, index)

    results = await asyncio.gather(*[process_wallet_limited(wallet, i) for i, wallet in enumerate(wallets)], return_exceptions=True)
    successful_wallets = sum(1 for r in results if r and r["success"])
    logger.success(f"Completed processing {successful_wallets}/{len(wallets)} wallets successfully")

    next_run_time = get_next_run_time()
    logger.info(f"Next run scheduled at: {next_run_time}")
    await display_countdown(next_run_time, interaction_count, proxies)

async def main():
    try:
        proxies = await load_proxies()
        await daily_run(None, proxies)
    except Exception as e:
        logger.error(f"Bot error: {str(e)}")
        next_run_time = get_next_run_time()
        logger.info(f"Next run scheduled at: {next_run_time}")
        proxies = await load_proxies()
        await display_countdown(next_run_time, None, perpetual)

if __name__ == "__main__":
    asyncio.run(main())
