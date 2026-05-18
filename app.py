from flask import Flask, request, jsonify
import requests
import urllib3
import base64
import json
from Crypto.Cipher import AES
from datetime import datetime
from google.protobuf.json_format import MessageToDict
from proto import FreeFire_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.json.sort_keys = False

http_session = requests.Session()

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
FF_NICKNAME_KEY = b"1e5898ccb8dfdd921f9bdea848768b64a201"

def pad(text: bytes) -> bytes:
    padding_length = 16 - (len(text) % 16)
    return text + bytes([padding_length] * padding_length)

def encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plaintext))

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

def convert_timestamps_to_human(data):
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (int, float)) and 1000000000 < v < 3000000000:
                try:
                    human_time = datetime.utcfromtimestamp(v).strftime('%Y-%m-%d %H:%M:%S UTC')
                    data[k] = f"{v} ({human_time})"
                except: pass
            elif isinstance(v, (dict, list)):
                convert_timestamps_to_human(v)
    elif isinstance(data, list):
        for i in range(len(data)):
            if isinstance(data[i], (int, float)) and 1000000000 < data[i] < 3000000000:
                try:
                    human_time = datetime.utcfromtimestamp(data[i]).strftime('%Y-%m-%d %H:%M:%S UTC')
                    data[i] = f"{data[i]} ({human_time})"
                except: pass
            elif isinstance(data[i], (dict, list)):
                convert_timestamps_to_human(data[i])
    return data

@app.route('/token', methods=['GET'])
def get_token():
    uid = request.args.get('uid')
    password = request.args.get('password')
    key = request.args.get('key')

    # Authentication key check
    if key != '@yashapis':
        return jsonify({
            "status": "error",
            "message": "Invalid API key"
        }), 401

    if not uid or not password:
        return jsonify({
            "status": "error",
            "message": "Missing parameters. Use /token?uid=xxx&password=xxx&key=@yashapis"
        }), 400

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
        # Step 1: Guest Auth
        r = http_session.post(oauth_url, json=payload, timeout=8)
        auth_data = r.json()

        inner = auth_data.get("data", {})
        acc_token = inner.get("access_token")
        open_id = inner.get("open_id")

        if not acc_token or not open_id:
            return jsonify({
                "status": "error",
                "message": "Guest auth failed"
            }), 401

        # Step 2: Major Login
        req_msg = FreeFire_pb2.LoginReq()
        req_msg.open_id = open_id
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

        resp = http_session.post("https://loginbp.ggpolarbear.com/MajorLogin", data=enc_data, headers=headers, verify=False, timeout=8)

        if resp.status_code == 200:
            res_msg = FreeFire_pb2.LoginRes()
            res_msg.ParseFromString(resp.content)
            major_dict = MessageToDict(res_msg, preserving_proto_field_name=True)

            nickname = extract_nickname_from_jwt(major_dict.get('token', ''))

            # Format response as requested
            response_data = {
                "access_token": acc_token,
                "account_id": major_dict.get('account_id', ''),
                "client_type": 2,
                "client_version": "1.123.1",
                "country_code": major_dict.get('country_code', 'IN'),
                "create": "",
                "emulator_score": major_dict.get('emulator_score', 100),
                "external_id": open_id,
                "external_type": 4,
                "external_uid": int(uid),
                "is_emulator": major_dict.get('is_emulator', True),
                "nickname": nickname,
                "open_id": open_id,
                "region": major_dict.get('noti_region', 'IND'),
                "release_version": "OB53",
                "token": major_dict.get('token', '')
            }

            return jsonify(response_data), 200
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)