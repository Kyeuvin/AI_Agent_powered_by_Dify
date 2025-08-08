from flask import Flask, request, jsonify, make_response
import requests
import hashlib
import json
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES
import base64
import struct
import socket
import time

app = Flask(__name__)

# 配置信息
CONFIG = {
    # 企业微信配置
    'CORP_ID': 'ww5a90dfd630815d26',
    'AGENT_ID': '1000004',
    'CORP_SECRET': 'kJoffzGOUP4KseynjfkESWyxHsLUSJN_mmP4QmPDb2Y',
    'TOKEN': 'gbiOBjx9IeIKo',  # 企业微信应用的Token
    'ENCODING_AES_KEY': '5V8ppBRuFTfT7kTlPgYiqXrISLkxYeBWjFbhCzL2NIC',  # 企业微信应用的EncodingAESKey

    # Dify配置
    'DIFY_API_BASE': 'http://192.168.1.18:8010',  # 您的Dify服务器内网地址
    'DIFY_API_KEY': 'app-GgOmbbzRXwobVRxcG901yIAr',  # Dify应用的API密钥
}


class WXBizMsgCrypt:
    """企业微信消息加解密类"""

    def __init__(self, token, encoding_aes_key, corp_id):
        self.token = token
        self.encoding_aes_key = encoding_aes_key
        self.corp_id = corp_id

    def sha1(self, token, timestamp, nonce, encrypt):
        """SHA1签名"""
        sortlist = [token, timestamp, nonce, encrypt]
        sortlist.sort()
        sha = hashlib.sha1("".join(sortlist).encode('utf-8'))
        return sha.hexdigest()

    def decrypt(self, text, corp_id):
        """解密消息"""
        try:
            key = base64.b64decode(self.encoding_aes_key + "=")
            text = base64.b64decode(text)

            iv = key[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(text)

            content = decrypted[16:]
            xml_len = struct.unpack("I", content[:4])[0]
            xml_content = content[4:xml_len + 4]
            from_corp_id = content[xml_len + 4:]

            if from_corp_id.decode('utf-8').rstrip('\0') != corp_id:
                return None

            return xml_content.decode('utf-8')
        except Exception as e:
            print(f"解密失败: {e}")
            return None


# 初始化加解密工具
wxcrypt = WXBizMsgCrypt(CONFIG['TOKEN'], CONFIG['ENCODING_AES_KEY'], CONFIG['CORP_ID'])


@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    """企业微信Webhook处理"""

    if request.method == 'GET':
        # 验证URL有效性
        return verify_url()
    elif request.method == 'POST':
        # 处理消息
        return handle_message()


def verify_url():
    """验证URL有效性"""
    msg_signature = request.args.get('msg_signature', '')
    timestamp = request.args.get('timestamp', '')
    nonce = request.args.get('nonce', '')
    echostr = request.args.get('echostr', '')

    # 验证签名
    signature = wxcrypt.sha1(CONFIG['TOKEN'], timestamp, nonce, echostr)

    if signature == msg_signature:
        # 解密echostr
        decrypted = wxcrypt.decrypt(echostr, CONFIG['CORP_ID'])
        if decrypted:
            return decrypted

    return 'fail', 400


def handle_message():
    """处理接收到的消息"""
    try:
        # 获取参数
        msg_signature = request.args.get('msg_signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')

        # 获取加密的消息体
        data = request.get_data()
        root = ET.fromstring(data)
        encrypt = root.find('Encrypt').text

        # 验证签名
        signature = wxcrypt.sha1(CONFIG['TOKEN'], timestamp, nonce, encrypt)
        if signature != msg_signature:
            return 'signature check failed', 400

        # 解密消息
        decrypted_msg = wxcrypt.decrypt(encrypt, CONFIG['CORP_ID'])
        if not decrypted_msg:
            return 'decrypt failed', 400

        # 解析XML消息
        msg_root = ET.fromstring(decrypted_msg)
        msg_type = msg_root.find('MsgType').text

        if msg_type == 'text':
            # 处理文本消息
            from_user = msg_root.find('FromUserName').text
            content = msg_root.find('Content').text

            # 调用Dify API获取回复
            reply = call_dify_api(content, from_user)

            # 发送回复给企业微信
            send_message_to_wechat(from_user, reply)

        return 'success'

    except Exception as e:
        print(f"处理消息失败: {e}")
        return 'error', 500


def call_dify_api(message, user_id):
    """调用Dify API获取回复"""
    try:
        url = f"{CONFIG['DIFY_API_BASE']}/v1/chat-messages"

        headers = {
            'Authorization': f"Bearer {CONFIG['DIFY_API_KEY']}",
            'Content-Type': 'application/json'
        }

        data = {
            "inputs": {},
            "query": message,
            "response_mode": "blocking",
            "conversation_id": "",
            "user": user_id
        }

        response = requests.post(url, headers=headers, json=data, timeout=30)

        if response.status_code == 200:
            result = response.json()
            return result.get('answer', '抱歉，我无法理解您的问题。')
        else:
            print(f"Dify API调用失败: {response.status_code}, {response.text}")
            return '服务暂时不可用，请稍后再试。'

    except Exception as e:
        print(f"调用Dify API异常: {e}")
        return '服务出现异常，请稍后再试。'


def send_message_to_wechat(to_user, content):
    """发送消息到企业微信"""
    try:
        # 获取access_token
        access_token = get_access_token()
        if not access_token:
            return False

        url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={access_token}"

        data = {
            "touser": to_user,
            "msgtype": "text",
            "agentid": CONFIG['AGENT_ID'],
            "text": {
                "content": content
            }
        }

        response = requests.post(url, json=data)
        result = response.json()

        if result.get('errcode') == 0:
            print(f"消息发送成功: {content}")
            return True
        else:
            print(f"消息发送失败: {result}")
            return False

    except Exception as e:
        print(f"发送消息异常: {e}")
        return False


def get_access_token():
    """获取企业微信access_token"""
    try:
        url = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
        params = {
            'corpid': CONFIG['CORP_ID'],
            'corpsecret': CONFIG['CORP_SECRET']
        }

        response = requests.get(url, params=params)
        result = response.json()

        if result.get('errcode') == 0:
            return result.get('access_token')
        else:
            print(f"获取access_token失败: {result}")
            return None

    except Exception as e:
        print(f"获取access_token异常: {e}")
        return None


if __name__ == '__main__':
    print("企业微信-Dify Webhook服务启动...")
    print(f"服务将连接到Dify服务器: {CONFIG['DIFY_API_BASE']}")
    app.run(host='0.0.0.0', port=11850, debug=True)