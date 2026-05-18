from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import base64
import json
from datetime import datetime, timezone, timedelta
import time
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Optional
import urllib3
import proto.my_pb2 as my_pb2
import proto.output_pb2 as output_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.json.sort_keys = False

SESSION = requests.Session()
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

PLATFORM_MAP = {
    3: "Facebook",
    4: "Guest",
    5: "VK",
    8: "Google",
    10: "AppleId",
    11: "X (Twitter)"
}

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
FF_NICKNAME_KEY = b"1e5898ccb8dfdd921f9bdea848768b64a201"

VALID_API_KEYS = ["DG-API-BUY-100"]

def verify_api_key(api_key: Optional[str]) -> bool:
    if not api_key:
        return False
    return api_key in VALID_API_KEYS

def pad_custom(text: bytes) -> bytes:
    padding_length = 16 - (len(text) % 16)
    return text + bytes([padding_length] * padding_length)

def encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad_custom(plaintext))

def format_ttl(seconds: int) -> str:
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours} hours, {minutes} mins, {secs} secs"

def decode_ff_nickname(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded)
        dec = bytearray()
        for i, b in enumerate(raw):
            dec.append(b ^ FF_NICKNAME_KEY[i % len(FF_NICKNAME_KEY)])
        return dec.decode('utf-8', errors='replace')
    except Exception:
        return "Unknown"

def extract_nickname_from_jwt(token: str) -> str:
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            payload_b64 = parts[1]
            payload_b64 += '=' * ((4 - len(payload_b64) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
            if 'nickname' in payload and isinstance(payload['nickname'], str):
                return decode_ff_nickname(payload['nickname'])
    except Exception:
        pass
    return "Unknown"

def remove_all_arrays(data):
    if isinstance(data, dict):
        keys_to_remove = [k for k, v in data.items() if isinstance(v, list)]
        for k in keys_to_remove:
            del data[k]
        for k, v in data.items():
            remove_all_arrays(v)
    elif isinstance(data, list):
        return None
    return data

def convert_timestamp_to_human_readable(timestamp_seconds: int) -> Dict[str, Any]:
    try:
        utc_time = datetime.fromtimestamp(timestamp_seconds, tz=timezone.utc)
        ist_offset = timedelta(hours=5, minutes=30)
        ist_time = utc_time + ist_offset
        current_time = int(time.time())
        time_remaining = timestamp_seconds - current_time
        days = time_remaining // (24 * 3600)
        hours = (time_remaining % (24 * 3600)) // 3600
        minutes = (time_remaining % 3600) // 60
        seconds = time_remaining % 60
        is_expired = time_remaining <= 0
        
        return {
            "timestamp": timestamp_seconds,
            "utc_time": utc_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "ist_time": ist_time.strftime("%Y-%m-%d %H:%M:%S IST"),
            "time_remaining_seconds": time_remaining,
            "time_remaining_human": f"{days} days, {hours} hours, {minutes} minutes, {seconds} seconds" if time_remaining > 0 else "Expired",
            "is_expired": is_expired,
            "days_remaining": days if not is_expired else 0,
            "hours_remaining": hours if not is_expired else 0,
            "minutes_remaining": minutes if not is_expired else 0,
            "seconds_remaining": seconds if not is_expired else 0
        }
    except Exception:
        return {
            "timestamp": timestamp_seconds,
            "utc_time": "Invalid timestamp",
            "ist_time": "Invalid timestamp",
            "time_remaining_seconds": 0,
            "time_remaining_human": "Invalid timestamp",
            "is_expired": True
        }

def get_token_inspect_data(access_token: str) -> Optional[Dict[str, Any]]:
    try:
        encoded_token = requests.utils.quote(access_token, safe='')
        resp = SESSION.get(
            f"https://100067.connect.garena.com/oauth/token/inspect?token={encoded_token}",
            timeout=15,
            verify=False,
            headers={
                "User-Agent": USERAGENT,
                "Accept": "application/json"
            }
        )
        
        if resp.status_code == 200:
            data = resp.json()
            return data
    except Exception as e:
        print(f"Error in get_token_inspect_data: {e}")
    
    return None

def decode_jwt_token(jwt_token: str) -> Optional[Dict[str, Any]]:
    try:
        parts = jwt_token.split('.')
        if len(parts) != 3:
            return None
        
        payload = parts[1]
        padding = 4 - (len(payload) % 4)
        if padding != 4:
            payload += '=' * padding
        
        decoded_bytes = base64.urlsafe_b64decode(payload)
        decoded_str = decoded_bytes.decode('utf-8')
        payload_data = json.loads(decoded_str)
        
        if 'nickname' in payload_data:
            try:
                decoded_nick = decode_ff_nickname(payload_data['nickname'])
                payload_data['nickname'] = decoded_nick
            except:
                pass
        
        if 'exp' in payload_data:
            exp_timestamp = payload_data['exp']
            payload_data['exp_human'] = convert_timestamp_to_human_readable(exp_timestamp)
        
        return payload_data
    except Exception as e:
        print(f"JWT decode error: {e}")
        return None

def extract_params_from_url(url: str) -> Dict[str, str]:
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        result = {}
        if 'access_token' in params:
            result['access_token'] = params['access_token'][0]
        if 'region' in params:
            result['region'] = params['region'][0]
        if 'account_id' in params:
            result['game_uid'] = params['account_id'][0]
        if 'nickname' in params:
            result['nickname'] = params['nickname'][0]
        if 'game' in params:
            result['game'] = params['game'][0]
        if 'lang' in params:
            result['language'] = params['lang'][0]
            
        return result
    except Exception as e:
        return {}

def eat_to_access_token(eat_token: str) -> Dict[str, Any]:
    try:
        callback_url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
        
        response = SESSION.get(
            callback_url,
            allow_redirects=True,
            timeout=30,
            verify=False
        )
        
        if 'help.garena.com' in response.url:
            params = extract_params_from_url(response.url)
            
            if 'access_token' in params:
                token_data = get_token_inspect_data(params['access_token'])
                
                if token_data:
                    platform_type = token_data.get('platform', 8)
                    platform_name = PLATFORM_MAP.get(platform_type, "Google")
                    
                    response_data = {
                        'access_token': params['access_token'],
                        'nickname': params.get('nickname', ''),
                        'open_id': token_data.get('open_id'),
                        'platform_name': platform_name,
                        'region': params.get('region'),
                        'uid': str(token_data.get('uid'))
                    }
                    
                    return response_data
        
        return None
        
    except Exception as e:
        print(f"EAT conversion error: {e}")
        return None

def login(uid, access_token, open_id, platform_type):
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    
    game_data = my_pb2.GameData()
    game_data.timestamp = str(int(time.time()))
    game_data.game_name = "Free Fire"
    game_data.game_version = 1
    game_data.version_code = "1.120.1"
    game_data.os_info = "iOS 18.4"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1170
    game_data.screen_height = 2532
    game_data.dpi = "460"
    game_data.cpu_info = "Apple A15 Bionic"
    game_data.total_ram = 6144
    game_data.gpu_name = "Apple GPU (5-core)"
    game_data.gpu_version = "Metal 3"
    
    game_data.user_id = str(uid)
    
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = str(open_id)
    game_data.access_token = str(access_token)
    game_data.platform_type = int(platform_type)
    
    game_data.field_99 = str(platform_type)
    game_data.field_100 = str(platform_type)
    
    serialized_data = game_data.SerializeToString()
    padded_data = pad(serialized_data, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(padded_data)
    
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": "OB53",
        "Content-Length": str(len(encrypted_data))
    }
    
    try:
        response = SESSION.post(url, data=encrypted_data, headers=headers, timeout=30, verify=False)
        
        if response.status_code == 200:
            jwt_msg = output_pb2.Garena_420()
            jwt_msg.ParseFromString(response.content)
            
            if jwt_msg.token:
                return jwt_msg.token
        else:
            error_text = response.content.decode().strip()
            
            if error_text == "BR_PLATFORM_INVALID_PLATFORM":
                return {"error": "INVALID_PLATFORM", "message": "this account is registered on another platform"}
            elif error_text == "BR_GOP_TOKEN_AUTH_FAILED":
                return {"error": "INVALID_TOKEN", "message": "AccessToken invalid."}
            elif error_text == "BR_PLATFORM_INVALID_OPENID":
                return {"error": "INVALID_OPENID", "message": "OpenID invalid."}
                
    except Exception as e:
        print(f"Login error: {e}")
    
    return None

def eat_to_jwt(eat_token: str) -> Dict[str, Any]:
    eat_result = eat_to_access_token(eat_token)
    
    if not eat_result:
        return {
            "success": False,
            "error": "INVALID_EAT_TOKEN",
            "message": "Unable to convert EAT token"
        }, 400
    
    access_token = eat_result.get('access_token')
    region = eat_result.get('region')
    game_uid = eat_result.get('uid')
    nickname = eat_result.get('nickname')
    open_id = eat_result.get('open_id')
    platform_name = eat_result.get('platform_name')
    
    platform_type = 8 if platform_name == "Google" else 4
    
    if nickname and '=' in nickname:
        try:
            nickname = decode_ff_nickname(nickname)
        except:
            pass
    
    jwt_token = login(game_uid, access_token, open_id, platform_type)
    
    if isinstance(jwt_token, dict) and 'error' in jwt_token:
        return {
            "success": False,
            "error": jwt_token.get("error"),
            "message": jwt_token.get("message")
        }, 400
    
    if not jwt_token:
        return {
            "success": False,
            "error": "JWT_GENERATION_FAILED",
            "message": "Failed to generate JWT token"
        }, 500
    
    response_data = {
        'access_token': access_token,
        'nickname': nickname,
        'open_id': open_id,
        'platform_name': platform_name,
        'region': region,
        'token': jwt_token,
        'uid': game_uid
    }
    
    response_data = remove_all_arrays(response_data)
    
    return response_data, 200

def decode_jwt(token: str) -> Dict[str, Any]:
    decoded = decode_jwt_token(token)
    
    if decoded:
        return {
            "success": True,
            "payload": decoded
        }, 200
    else:
        return {
            "success": False,
            "error": "INVALID_JWT",
            "message": "Failed to decode JWT token"
        }, 400

@app.route('/token', methods=['GET'])
def unified_token():
    api_key = request.args.get('key')
    
    if not verify_api_key(api_key):
        return jsonify({
            "error": "INVALID_API_KEY",
            "message": "Valid API key is required. Use ?key=DG-API-BUY-100"
        }), 401
    
    access_token = request.args.get('access')
    uid = request.args.get('uid')
    password = request.args.get('password')
    eat = request.args.get('eat')
    decode = request.args.get('decode')
    
    if access_token:
        token_data = get_token_inspect_data(access_token)
        
        if not token_data:
            return jsonify({
                "success": False,
                "error": "INVALID_TOKEN",
                "message": "AccessToken is invalid or expired"
            }), 400
        
        open_id = token_data.get('open_id')
        platform_type = token_data.get('platform', 4)
        uid_val = token_data.get('uid')
        
        uid_str = str(uid_val) if uid_val else ""
        platform_type_int = int(platform_type) if platform_type else 4
        open_id_str = str(open_id) if open_id else ""
        
        if not open_id_str:
            return jsonify({
                "success": False,
                "error": "MISSING_DATA",
                "message": "Could not extract open_id from access_token"
            }), 400
        
        jwt_token = login(uid_str, access_token, open_id_str, platform_type_int)
        
        if isinstance(jwt_token, dict) and 'error' in jwt_token:
            return jsonify({
                "success": False,
                "error": jwt_token.get("error"),
                "message": jwt_token.get("message")
            }), 400
        
        if not jwt_token:
            return jsonify({
                "success": False,
                "error": "JWT_GENERATION_FAILED",
                "message": "Failed to generate JWT token. Account may be unregistered or banned."
            }), 500
        
        response_data = {
            "access_token": access_token,
            "account_id": uid_str,
            "client_type": 2,
            "client_version": "1.123.1",
            "country_code": token_data.get('country_code', 'IN'),
            "create": "",
            "emulator_score": 100,
            "external_id": open_id_str,
            "external_type": platform_type_int,
            "external_uid": int(uid_str) if uid_str.isdigit() else 0,
            "is_emulator": True,
            "nickname": token_data.get('nickname', ''),
            "open_id": open_id_str,
            "region": token_data.get('region', 'IND'),
            "release_version": "OB53",
            "token": jwt_token
        }
        
        return jsonify(response_data)
    
    elif uid and password:
        from proto.FreeFire_pb2 import LoginReq, LoginRes
        from google.protobuf.json_format import MessageToDict
        
        oauth_url = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
        payload = {
            "client_id": 100067,
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_type": 2,
            "password": password,
            "response_type": "token",
            "uid": int(uid)
        }
        
        try:
            r = SESSION.post(oauth_url, json=payload, timeout=8)
            auth_data = r.json()
            
            inner = auth_data.get("data", {})
            acc_token = inner.get("access_token")
            open_id_val = inner.get("open_id")
            
            if not acc_token or not open_id_val:
                return jsonify({
                    "status": "error",
                    "message": "Auth tokens not found"
                }), 401
            
            req_msg = LoginReq()
            req_msg.open_id = open_id_val
            req_msg.open_id_type = "4"
            req_msg.login_token = acc_token
            req_msg.orign_platform_type = "4"
            
            enc_data = encrypt(req_msg.SerializeToString())
            headers = {
                "X-GA": "v1 1",
                "ReleaseVersion": "OB53",
                "Content-Type": "application/octet-stream",
                "User-Agent": USERAGENT
            }
            
            resp = SESSION.post("https://loginbp.ggpolarbear.com/MajorLogin", data=enc_data, headers=headers, verify=False, timeout=8)
            
            if resp.status_code == 200:
                res_msg = LoginRes()
                res_msg.ParseFromString(resp.content)
                major_dict = MessageToDict(res_msg, preserving_proto_field_name=True)
                
                if 'ttl' in major_dict:
                    major_dict['ttl'] = format_ttl(int(major_dict['ttl']))
                
                nickname = "Unknown"
                token_val = None
                if 'token' in major_dict:
                    token_val = major_dict['token']
                    nickname = extract_nickname_from_jwt(token_val)
                
                token_data = get_token_inspect_data(acc_token)
                
                final_response = {
                    "access_token": acc_token,
                    "account_id": major_dict.get('account_id', ''),
                    "client_type": 2,
                    "client_version": "1.123.1",
                    "country_code": token_data.get('country_code', 'IN') if token_data else 'IN',
                    "create": "",
                    "emulator_score": 100,
                    "external_id": open_id_val,
                    "external_type": 4,
                    "external_uid": int(uid),
                    "is_emulator": True,
                    "nickname": nickname,
                    "open_id": open_id_val,
                    "region": "IND",
                    "release_version": "OB53",
                    "token": token_val
                }
                
                final_response = remove_all_arrays(final_response)
                
                return jsonify(final_response), 200
            else:
                return jsonify({
                    "status": "error",
                    "message": f"MajorLogin failed with status {resp.status_code}"
                }), 502
                
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e)
            }), 500
    
    elif eat:
        response, status_code = eat_to_jwt(eat)
        return jsonify(response), status_code
    
    elif decode:
        response, status_code = decode_jwt(decode)
        return jsonify(response), status_code
    
    else:
        return jsonify({
            "error": "MISSING_PARAMETER",
            "message": "API key required. Use one of: /token?key=DG-API-BUY-100&access=xxx OR /token?key=DG-API-BUY-100&uid=xxx&password=xxx OR /token?key=DG-API-BUY-100&eat=xxx OR /token?key=DG-API-BUY-100&decode=xxx",
            "examples": {
                "access_token": "/token?key=DG-API-BUY-100&access=xxx",
                "guest_login": "/token?key=DG-API-BUY-100&uid=4719165478&password=xxx",
                "eat_token": "/token?key=DG-API-BUY-100&eat=xxx",
                "decode_jwt": "/token?key=DG-API-BUY-100&decode=eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.xxx"
            }
        }), 400

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)