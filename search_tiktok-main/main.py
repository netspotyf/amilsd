import requests
from threading import Thread
import hashlib
import json
import requests
import uuid
from time import time
from copy import deepcopy
import random
import hashlib
import json
import requests
import uuid
import random
import secrets
import time
from user_agent import generate_user_agent
from time import time
from copy import deepcopy
import random
from flask import Flask, request, jsonify
class CryptoHeaders:
    def __init__(self, param="", stub="", cookie=""):
        self.param = param
        self.stub = stub
        self.cookie = cookie
        self.current_time = int(time())
        self.gorgon_values = self._compute_gorgon_values()
        self.debug_values = []
        self.state = []
        self.intermediate_values = []
        self.final_values = []

    def _hash_to_bytes(self, data):
        if data:
            return hashlib.md5(data.encode('utf-8')).digest()
        return b'\x00' * 16

    def generate_session_ids(self):
        new_uuid = str(uuid.uuid4()).replace('-', '')
        sid_tt = f"{new_uuid[:16]}"
        sessionid = f"{new_uuid}"
        sessionid_ss = f"{new_uuid}"
        return sid_tt, sessionid, sessionid_ss

    def _compute_gorgon_values(self):
        gorgon = []
        gorgon.extend(self._hash_to_bytes(self.param))
        gorgon.extend(self._hash_to_bytes(self.stub))
        gorgon.extend(self._hash_to_bytes(self.cookie))
        gorgon.extend([0x00, 0x08, 0x10, 0x09])
        gorgon.extend(self._int_to_bytes(self.current_time))
    #    print("Gorgon:", [self._format_hex(b) for b in gorgon])
        return gorgon

    def _int_to_bytes(self, value):
        return [(value >> (8 * i)) & 0xFF for i in range(4)]

    def _format_hex(self, num):
        return f"{num:02x}"

    def _swap_nibbles(self, num):
        hex_str = f"{num:02x}"
        return int(hex_str[1] + hex_str[0], 16)

    def _reverse_bits(self, num):
        return int(f"{num:08b}"[::-1], 2)

    def _generate_state(self):
        state = list(range(256))
        tmp = ''
        for i in range(256):
            prev = tmp if tmp else state[i - 1]
            modifier = self.gorgon_values[i % 8]
            if prev == 0x05 and i != 1 and tmp != 0x05:
                prev = 0
            new_value = (prev + i + modifier) % 256
            tmp = new_value if new_value < i else ''
            state[i] = state[new_value]
        self.state = state
    #    print("Generated e:", [self._format_hex(b) for b in state])
        return state

    def _initialize_debug(self, state):
        debug = [0] * 20
        temp_state = deepcopy(state)
        for i in range(20):
            prev_value = debug[i - 1] if i > 0 else 0
            new_index = (state[i + 1] + prev_value) % 256
            debug[i] = temp_state[new_index]
            double_value = (debug[i] * 2) % 256
            temp_state[i + 1] = temp_state[double_value]
            debug[i] ^= temp_state[double_value]
        self.debug_values = debug
    #    print("Initialized :", [self._format_hex(b) for b in debug])
        return debug

    def _calculate_values(self, debug):
        for i in range(20):
            byte = debug[i]
            swapped = self._swap_nibbles(byte)
            next_byte = debug[(i + 1) % 20]
            xored = swapped ^ next_byte
            reversed_bits = self._reverse_bits(xored)
            modified = reversed_bits ^ 20
            debug[i] = (~modified) & 0xFF
            self.intermediate_values.append({
                'step': i,
                'byte': self._format_hex(byte),
                'swapped': self._format_hex(swapped),
                'xored': self._format_hex(xored),
                'reversed_bits': self._format_hex(reversed_bits),
                'modified': self._format_hex(modified),
                'final': self._format_hex(debug[i])
            })
    #    print("Intermediate ", self.intermediate_values)
        return debug

    def generate_headers(self):
        sid_tt, sessionid, sessionid_ss = self.generate_session_ids()
        state = self._generate_state()
        debug = self._initialize_debug(state)
        calculated_values = self._calculate_values(debug)
        result = ''.join(self._format_hex(byte) for byte in calculated_values)
        xgorgon = f"8402{self._format_hex(self.gorgon_values[7])}{self._format_hex(self.gorgon_values[3])}" \
                  f"{self._format_hex(self.gorgon_values[1])}{self._format_hex(self.gorgon_values[6])}{result}"
 #       print("X-Gorgon :", xgorgon)
#        print("X-Khronos:", str(self.current_time))
        self.final_values = {
            'X-Gorgon': xgorgon,
            'X-Khronos': str(self.current_time),
            'sessionid': sessionid,
            'sid_tt': sid_tt,
            'sessionid_ss': sessionid_ss
        }
        return self.final_values


    def compute_stub(data):
        if isinstance(data, dict):
            data = json.dumps(data)
        if isinstance(data, str):
            data = data.encode('utf-8')
        if not data:
            return "00000000000000000000000000000000"
        stub = hashlib.md5(data).hexdigest().upper()
 #       print("Computed ", stub)
        return stub

def qredes(h):
    while True:
        try:
            cok={}
            ua=generate_user_agent()
            sessionid=h['sessionid']
            sid_tt=h['sid_tt']
            sessionid_ss=h['sessionid_ss']
            headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en-US,en;q=0.9',
    'priority': 'u=0, i',
    'sec-ch-ua': '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': ua,
}
            cookies = requests.get('https://www.tiktok.com/', headers=headers,cookies={'sessionid': sessionid,'sid_tt': sid_tt,'sessionid_ss': sessionid_ss}).cookies.get_dict()

            if 'ak_bmsc' in cookies:
                ak_bmsc= cookies['ak_bmsc']
                cok['ak_bmsc']= ak_bmsc
            if 'tt_csrf_token' in cookies:
                tt_csrf_token = cookies['tt_csrf_token']
                cok['tt_csrf_token']= tt_csrf_token
            if 'bm_sv' in cookies:
                bm_sv= cookies['bm_sv']
            if 'ttwid' in cookies:
                ttwid = cookies['ttwid']
            headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'en',
    'dnt': '1',
    'priority': 'u=0, i',
    'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Microsoft Edge";v="128"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': ua,
}
            cookies = requests.get('https://www.tiktok.com/explore', cookies={'sessionid': sessionid,'sid_tt': sid_tt,'sessionid_ss': sessionid_ss}, headers=headers).cookies.get_dict()
            if 'ak_bmsc' in cookies:
                ak_bmsc= cookies['ak_bmsc']
                cok['ak_bmsc']= ak_bmsc
            if 'tt_csrf_token' in cookies:
                tt_csrf_token= cookies['tt_csrf_token']
                cok['tt_csrf_token']= tt_csrf_token
            if 'bm_sv' in cookies:
                bm_sv= cookies['bm_sv']
            if 'ttwid' in cookies:
                ttwid= cookies['ttwid']
            headers = {
    'accept': '*/*',
    'accept-language': 'en',
    'dnt': '1',
    'priority': 'u=1, i',
    'referer': 'https://www.tiktok.com/search/user?q=hdu&t=1724762414501',
    'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Microsoft Edge";v="128"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': ua,
}
            response = requests.get(
    'https://www.tiktok.com/api/search/user/full/?WebIdLastTime=1725100549&aid=1988&app_language=en&app_name=tiktok_web&browser_language=en&browser_name=Mozilla&browser_online=true&browser_platform=Win32&browser_version=5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F128.0.0.0%20Safari%2F537.36%20Edg%2F128.0.0.0&channel=tiktok_web&cookie_enabled=true&cursor=0&data_collection_enabled=false&device_id=7409250368918095366&device_platform=web_pc&focus_state=true&from_page=search&history_len=4&is_fullscreen=false&is_page_visible=true&keyword=ojhuhu&odinId=7409250173857498117&os=windows&priority_region=&referer=&region=MA&screen_height=900&screen_width=1600&tz_name=Africa%2FCasablanca&user_is_login=false&web_search_code=%7B%22tiktok%22%3A%7B%22client_params_x%22%3A%7B%22search_engine%22%3A%7B%22ies_mt_user_live_video_card_use_libra%22%3A1%2C%22mt_search_general_user_live_card%22%3A1%7D%7D%2C%22search_server%22%3A%7B%7D%7D%7D&webcast_language=en&msToken=0cQv8pO2f2fY0l7TYQMjel42WAuQdv_pSA1vhCs9D39aTy9q39oM1Uxb-ivdr7mY4UXa-n8c3aXRUlg09t02TUjnmt_1PoGb32ZhKdLCrHTxw93E-vHV2ppIHrFAapuS-WQKlSJi-0sLbbHWZDifAjJFTQ==&X-Bogus=DFSzswVEc-vAN9dMtIR9flSwXQ0B&_signature=_02B4Z6wo00001aIHbOgAAIDBKD2clDiitkGiB2hAAA5Ua7',
    cookies={'sessionid': sessionid,'sid_tt': sid_tt,'sessionid_ss': sessionid_ss},
    headers=headers,
).cookies.get_dict()
            msToken= response['msToken']
            
 
           # if bm_sv:
           #     cok['bm_sv']= bm_sv
            cok['ttwid']=ttwid
            cok['msToken']=msToken
            cok['sessionid_ss']=sessionid_ss
            cok['sessionid']=sessionid
            cok['sid_tt']=sid_tt

            return cok
        except Exception as e:print(str(e))

app=Flask(__name__)
@app.route('/')
def search():
    keyword=request.form.get('keyword')
    cookies=request.cookies.to_dict()
    cookies=json.dumps(cookies)
    cookies = json.loads(str(cookies))
    if keyword == None:
        return {
            'errors':['keyword is required']
        }
    p='WebIdLastTime=1725100549&aid=1988&app_language=en&app_name=tiktok_web&browser_language=en&browser_name=Mozilla&browser_online=true&browser_platform=Win32&browser_version=5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F128.0.0.0%20Safari%2F537.36%20Edg%2F128.0.0.0&channel=tiktok_web&cookie_enabled=true&cursor=0&data_collection_enabled=false&device_id=7409250368918095366&device_platform=web_pc&focus_state=true&from_page=search&history_len=4&is_fullscreen=false&is_page_visible=true&keyword={}&odinId=7409250173857498117&os=windows&priority_region=&referer=&region=MA&screen_height=900&screen_width=1600&tz_name=Africa%2FCasablanca&user_is_login=false&web_search_code=%7B%22tiktok%22%3A%7B%22client_params_x%22%3A%7B%22search_engine%22%3A%7B%22ies_mt_user_live_video_card_use_libra%22%3A1%2C%22mt_search_general_user_live_card%22%3A1%7D%7D%2C%22search_server%22%3A%7B%7D%7D%7D&webcast_language=en&msToken=0cQv8pO2f2fY0l7TYQMjel42WAuQdv_pSA1vhCs9D39aTy9q39oM1Uxb-ivdr7mY4UXa-n8c3aXRUlg09t02TUjnmt_1PoGb32ZhKdLCrHTxw93E-vHV2ppIHrFAapuS-WQKlSJi-0sLbbHWZDifAjJFTQ==&X-Bogus=DFSzswVEc-vAN9dMtIR9flSwXQ0B&_signature=_02B4Z6wo00001aIHbOgAAIDBKD2clDiitkGiB2hAAA5Ua7'.format(keyword)
    if 'msToken' and 'ttwid' in cookies:
        crypto_headers = CryptoHeaders(param=p, cookie='')
        h = crypto_headers.generate_headers()   
    else:
        crypto_headers = CryptoHeaders(param=p, cookie='')
        h = crypto_headers.generate_headers()
        cookies=qredes(h)
      #  print(cookies)

    while True:
        try:

            headers = {
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'priority': 'u=1, i',
    'referer': 'https://www.tiktok.com/search/user?q={}'.format(keyword),
    'sec-ch-ua': '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': generate_user_agent(),
    'X-Gorgon':h['X-Gorgon'],
    'X-Khronos':h['X-Khronos'],
}
            p = params = {
                "WebIdLastTime": str(time()).split('.')[0],
                "aid": "1988",
                "app_language": "en",
                "app_name": "tiktok_web",
                "browser_language": "en",
                "browser_name": "Mozilla",
                "browser_online": "true",
                "browser_platform": "Win32",
                "browser_version": f"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(90, 130)}.0.0.0 Safari/537.36 Edg/{random.randint(90, 130)}.0.0.0",
                "channel": "tiktok_web",
                "cookie_enabled": "true",
                "cursor": "0",
                "data_collection_enabled": "false",
                "device_id": str(random.randint(1000000000000000000, 9999999999999999999)),
                "device_platform": "web_pc",
                "focus_state": "true",
                "from_page": "search",
                "history_len": str(random.randint(1, 10)),
                "is_fullscreen": "false",
                "is_page_visible": "true",
                "keyword": keyword,
                "odinId": str(random.randint(1000000000000000000, 9999999999999999999)),
                "os": "windows",
                "priority_region": "",
                "referer": "",
                "region": random.choice(["MA", "US", "CA", "FR", "DE"]),
                "screen_height": str(random.choice([720, 900, 1080, 1440])),
                "screen_width": str(random.choice([1280, 1600, 1920, 2560])),
                "tz_name": random.choice(["Africa/Casablanca", "America/New_York", "Europe/Berlin"]),
                "user_is_login": "false",
                "web_search_code": '{"tiktok":{"client_params_x":{"search_engine":{"ies_mt_user_live_video_card_use_libra":1,"mt_search_general_user_live_card":1}},"search_server":{}}}',
                "webcast_language": "en",
                "msToken": cookies['msToken'],
                "X-Bogus": secrets.token_urlsafe(32),
                "_signature": secrets.token_urlsafe(64)
            }
            response = requests.get(
    'https://www.tiktok.com/api/search/user/full/',
    cookies=cookies,
    headers=headers,
    params=p
)
            if 'msToken' in response.cookies.get_dict():
                
                cookies['msToken']=response.cookies.get_dict()['msToken']

            if 'user_list' not in response.json():
             #   print(response.json())
                return {'errors':['error cookies']}
            else:
                return {
                    'cookies':cookies,
                    'response':response.json()}
        except Exception as e:
       #     print(str(e))
            return {'errors':['error cookies']}

