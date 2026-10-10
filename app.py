# ========================== IMPORTS ==========================
import os
import json
import time
import random
import pytz
import threading
import asyncio
import logging
import warnings
import binascii
import base64
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import aiohttp
import urllib3
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import like_pb2
import like_count_pb2
import uid_generator_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter('ignore')

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# ========================== CONFIG ==========================
TOKEN_BATCH_SIZE = 100
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'
GUEST_API_URL = "https://sheihk-jwt-ob55.up.railway.app/token"
ACCOUNTS_FILE = "accounts.txt"          # uid:pass per line
VISIT_TOKEN_FILE = "token_bd_visit.json"  # optional
MAX_WORKERS = 20                         # parallel fetch limit

# BD-only endpoints
BD_LIKE_URL    = "https://clientbp.ggpolarbear.com/LikeProfile"
BD_PROFILE_URL = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
BD_REGION      = "BD"

# ========================== STATE ==========================
token_cache = {"BD": [], "BD_visit": []}
current_batch_index = 0
batch_lock = threading.Lock()
refresh_lock = threading.Lock()
refresh_in_progress = False
last_refresh_time = None

# ========================== TIME ==========================
def get_bd_time():
    return datetime.now(pytz.timezone('Asia/Dhaka'))

# ========================== CRYPTO ==========================
def encrypt_message(plaintext):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return binascii.hexlify(cipher.encrypt(pad(plaintext, AES.block_size))).decode()
    except Exception as e:
        app.logger.error(f"Encryption error: {e}")
        return None

def create_protobuf_message(user_id, region):
    m = like_pb2.like()
    m.uid = int(user_id)
    m.region = region
    return m.SerializeToString()

def create_protobuf_for_profile_check(uid):
    m = uid_generator_pb2.uid_generator()
    m.krishna_ = int(uid)
    m.teamXdarks = 1
    return m.SerializeToString()

def enc_profile_check_payload(uid):
    pb = create_protobuf_for_profile_check(uid)
    return encrypt_message(pb) if pb else None

def decode_protobuf_profile_info(binary):
    try:
        info = like_count_pb2.Info()
        info.ParseFromString(binary)
        return info
    except Exception as e:
        app.logger.error(f"PB decode error: {e}")
        return None

# ========================== JWT ==========================
def decode_jwt_payload(token):
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return {}
        payload = parts[1] + '=' * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}

# ========================== ACCOUNTS PARSER ==========================
def load_credentials():
    """
    accounts.txt → list of {"uid":..., "pass":...}
    Format: uid:pass (per line). '#' = comment, empty = skip.
    """
    creds = []
    if not os.path.exists(ACCOUNTS_FILE):
        app.logger.warning(f"{ACCOUNTS_FILE} not found.")
        return creds
    try:
        with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    app.logger.warning(f"Line {lineno}: invalid format (need uid:pass)")
                    continue
                uid, pwd = line.split(":", 1)
                uid, pwd = uid.strip(), pwd.strip()
                if uid and pwd:
                    creds.append({"uid": uid, "pass": pwd})
    except Exception as e:
        app.logger.error(f"Accounts load error: {e}")
    return creds

# ========================== TOKEN FETCH ==========================
def fetch_guest_token(uid, password):
    """Guest API → single BD token"""
    try:
        r = requests.get(
            GUEST_API_URL,
            params={"uid": uid, "pass": password},
            timeout=10, verify=False
        )
        data = r.json()
        if str(data.get("Status", "")).lower() != "success":
            app.logger.warning(f"[{uid}] API status: {data.get('Status')}")
            return None
        tok = data.get("Token")
        if not tok:
            app.logger.warning(f"[{uid}] No Token in response")
            return None
        jwt = decode_jwt_payload(tok)
        region = jwt.get("noti_region") or jwt.get("lock_region") or "BD"
        return {
            "token": tok,
            "uid": uid,
            "region": region,
            "name": data.get("Name", ""),
            "level": data.get("Level", 0),
        }
    except Exception as e:
        app.logger.error(f"[{uid}] fetch failed: {e}")
        return None

def build_bd_tokens():
    """Parallel fetch — সব credential থেকে token"""
    creds = load_credentials()
    if not creds:
        app.logger.warning(f"No credentials in {ACCOUNTS_FILE}")
        return []

    app.logger.info(f"Fetching {len(creds)} account(s) in parallel...")
    tokens = []
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(creds))) as ex:
        futures = {ex.submit(fetch_guest_token, c["uid"], c["pass"]): c["uid"] for c in creds}
        for fut in as_completed(futures):
            uid = futures[fut]
            try:
                t = fut.result()
                if t:
                    tokens.append(t)
                    app.logger.info(f"[OK] {uid}")
                else:
                    app.logger.warning(f"[FAIL] {uid}")
            except Exception as e:
                app.logger.error(f"[ERR] {uid}: {e}")
    return tokens

def load_visit_tokens():
    try:
        if os.path.exists(VISIT_TOKEN_FILE):
            with open(VISIT_TOKEN_FILE, "r") as f:
                arr = json.load(f)
                return [
                    {"token": x.get("token") or x.get("Token"),
                     "uid": x.get("uid"), "region": "BD"}
                    for x in arr if (x.get("token") or x.get("Token"))
                ]
    except Exception as e:
        app.logger.error(f"Visit token load error: {e}")
    return []

# ========================== REFRESH ==========================
def auto_refresh_tokens_job():
    global token_cache, refresh_in_progress, last_refresh_time

    with refresh_lock:
        if refresh_in_progress:
            return
        refresh_in_progress = True

    now = get_bd_time()
    app.logger.info(f"[REFRESH START] {now.strftime('%Y-%m-%d %H:%M:%S')} BST")

    try:
        bd_tokens = build_bd_tokens()
        visit_tokens = load_visit_tokens()

        if not bd_tokens:
            app.logger.warning("No BD tokens fetched — keeping previous cache.")
        else:
            with refresh_lock:
                token_cache["BD"] = bd_tokens
                if visit_tokens:
                    token_cache["BD_visit"] = visit_tokens
            app.logger.info(f"[REFRESH OK] BD={len(bd_tokens)} visit={len(token_cache['BD_visit'])}")

        with refresh_lock:
            last_refresh_time = now
    except Exception as e:
        app.logger.error(f"Refresh failed: {e}")
    finally:
        with refresh_lock:
            refresh_in_progress = False

def scheduled_8hr_checker():
    app.logger.info("8-Hour Scheduler started...")
    auto_refresh_tokens_job()
    INTERVAL = 8 * 3600
    while True:
        try:
            time.sleep(60)
            if last_refresh_time:
                elapsed = (get_bd_time() - last_refresh_time).total_seconds()
                if elapsed >= INTERVAL:
                    auto_refresh_tokens_job()
        except Exception as e:
            app.logger.error(f"Scheduler error: {e}")
            time.sleep(60)

def start_background_scheduler():
    threading.Thread(target=scheduled_8hr_checker, daemon=True).start()
    app.logger.info("Scheduler thread started.")

# ========================== TOKEN ACCESS ==========================
def get_bd_tokens(for_visit=False):
    key = "BD_visit" if for_visit else "BD"
    with refresh_lock:
        cached = token_cache.get(key, [])
    if cached:
        return cached
    if not for_visit:
        return build_bd_tokens()
    return []

def get_next_batch(all_tokens):
    global current_batch_index
    if not all_tokens:
        return []
    total = len(all_tokens)
    if total <= TOKEN_BATCH_SIZE:
        return all_tokens
    with batch_lock:
        start = current_batch_index
        end = start + TOKEN_BATCH_SIZE
        if end > total:
            remaining = end - total
            batch = all_tokens[start:total] + all_tokens[0:remaining]
        else:
            batch = all_tokens[start:end]
        current_batch_index = (start + TOKEN_BATCH_SIZE) % total
        return batch

def get_random_batch(all_tokens):
    if not all_tokens:
        return []
    if len(all_tokens) <= TOKEN_BATCH_SIZE:
        return all_tokens.copy()
    return random.sample(all_tokens, TOKEN_BATCH_SIZE)

# ========================== NETWORK ==========================
async def send_single_like(encrypted_payload, token_dict, url):
    token_value = token_dict.get("token", "")
    if not token_value:
        return 999
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token_value}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB55"
    }
    try:
        edata = bytes.fromhex(encrypted_payload)
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.post(url, data=edata, headers=headers) as r:
                return r.status
    except Exception:
        return 997

async def send_likes_batch(uid, region, url, tokens):
    if not tokens:
        return []
    pb = create_protobuf_message(uid, region)
    enc = encrypt_message(pb)
    tasks = [send_single_like(enc, t, url) for t in tokens]
    return await asyncio.gather(*tasks, return_exceptions=True)

def make_profile_check(encrypted_payload, token_dict):
    token_value = token_dict.get("token", "")
    if not token_value:
        return None
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token_value}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB53"
    }
    try:
        r = requests.post(BD_PROFILE_URL, data=bytes.fromhex(encrypted_payload),
                          headers=headers, verify=False, timeout=5)
        r.raise_for_status()
        return decode_protobuf_profile_info(r.content)
    except Exception as e:
        app.logger.error(f"Profile check error: {e}")
        return None

# ========================== ROUTES ==========================
@app.route('/like', methods=['GET'])
def handle_like():
    uid_param = request.args.get("uid")
    server_name = request.args.get("server_name", "BD").upper()
    use_random = request.args.get("random", "false").lower() == "true"

    if not uid_param:
        return jsonify({"error": "uid required"}), 400
    if server_name != "BD":
        return jsonify({"error": "Only BD server supported."}), 400

    all_tokens = get_bd_tokens(for_visit=False)
    if not all_tokens:
        return jsonify({"error": "No BD tokens available. Try /jwt first."}), 500

    visit_tokens = get_bd_tokens(for_visit=True)
    visit_token = visit_tokens[0] if visit_tokens else all_tokens[0]

    tokens_for_like = get_random_batch(all_tokens) if use_random else get_next_batch(all_tokens)
    enc_uid = enc_profile_check_payload(uid_param)

    before = make_profile_check(enc_uid, visit_token)
    before_likes = 0
    if before and hasattr(before, 'AccountInfo'):
        before_likes = int(before.AccountInfo.Likes)

    if tokens_for_like:
        asyncio.run(send_likes_batch(uid_param, BD_REGION, BD_LIKE_URL, tokens_for_like))

    after = make_profile_check(enc_uid, visit_token)
    after_likes = before_likes
    nick = "N/A"
    real_uid = int(uid_param)
    if after and hasattr(after, 'AccountInfo'):
        after_likes = int(after.AccountInfo.Likes)
        real_uid = int(after.AccountInfo.UID)
        if after.AccountInfo.PlayerNickname:
            nick = str(after.AccountInfo.PlayerNickname)

    inc = after_likes - before_likes
    status = 1 if inc > 0 else (2 if inc == 0 else 3)

    return jsonify({
        "LikesGivenByAPI": inc,
        "LikesafterCommand": after_likes,
        "LikesbeforeCommand": before_likes,
        "PlayerNickname": nick,
        "UID": real_uid,
        "status": status,
        "Owner": "Sheihk Anamul",
        "Instagram": "anamul9.9",
        "Youtube": "ai-bot987",
        "Note": f"BD only | {'random' if use_random else 'rotating'} batch of {len(tokens_for_like)} tokens"
    })

@app.route('/ch', methods=['GET'])
def status():
    with refresh_lock:
        bd_count = len(token_cache.get("BD", []))
        visit_count = len(token_cache.get("BD_visit", []))
    return jsonify({
        "server": "BD",
        "refresh_in_progress": refresh_in_progress,
        "last_refresh": str(last_refresh_time) if last_refresh_time else "never",
        "bd_tokens": bd_count,
        "bd_visit_tokens": visit_count,
    })

@app.route('/jwt', methods=['GET', 'POST'])
def manual_refresh():
    if refresh_in_progress:
        return jsonify({"message": "Refresh already in progress"}), 202
    threading.Thread(target=auto_refresh_tokens_job, daemon=True).start()
    return jsonify({"message": "BD token refresh triggered."}), 200

# ========================== MAIN ==========================
if __name__ == '__main__':
    start_background_scheduler()
    app.run(host='0.0.0.0', port=5002, debug=False, use_reloader=False)