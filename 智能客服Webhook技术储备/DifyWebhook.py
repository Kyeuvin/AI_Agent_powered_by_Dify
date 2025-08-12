import ssl
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

# 添加消息去重机制
processed_messages = set()  # 存储已处理的消息ID
message_cursors = {}  # 存储每个客服的cursor
MAX_PROCESSED_MESSAGES = 10000  # 最大存储的已处理消息数量

# 配置信息
CONFIG = {
    # 企业微信配置
    'CORP_ID': 'ww5a90dfd630815d26',
    'AGENT_ID': '1000004',
    'CORP_SECRET': 'kJoffzGOUP4KseynjfkESWyxHsLUSJN_mmP4QmPDb2Y',
    'TOKEN': 'gbiOBjx9IeIKo',  # 企业微信应用的Token
    'ENCODING_AES_KEY': '5V8ppBRuFTfT7kTlPgYiqXrISLkxYeBWjFbhCzL2NIC',  # 企业微信应用的EncodingAESKey

    # Dify配置
    'DIFY_API_BASE': 'http://192.168.1.18:8010/v1',  # 您的Dify服务器内网地址
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

    # def decrypt(self, text, corp_id):
    #     """解密消息"""
    #     try:
    #         key = base64.b64decode(self.encoding_aes_key + "=")
    #         text = base64.b64decode(text)
    #
    #         iv = key[:16]
    #         cipher = AES.new(key, AES.MODE_CBC, iv)
    #         decrypted = cipher.decrypt(text)
    #
    #         content = decrypted[16:]
    #         xml_len = struct.unpack("I", content[:4])[0]
    #         xml_content = content[4:xml_len + 4]
    #         from_corp_id = content[xml_len + 4:]
    #
    #         if from_corp_id.decode('utf-8').rstrip('\0') != corp_id:
    #             return None
    #
    #         return xml_content.decode('utf-8')
    #     except Exception as e:
    #         print(f"解密失败: {e}")
    #         return None
    #
    def decrypt(self, text, corp_id):
        """解密消息"""
        try:
            # 补齐Base64填充
            key_with_padding = self.encoding_aes_key + "=" * (4 - len(self.encoding_aes_key) % 4)
            key = base64.b64decode(key_with_padding)

            # 补齐Base64填充
            msg_with_padding = text + "=" * (4 - len(text) % 4)
            encrypt_msg_bytes = base64.b64decode(msg_with_padding)

            # AES解密
            iv = key[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypt_msg_bytes)

            # 去除PKCS7填充
            pad_len = decrypted[-1]
            if isinstance(pad_len, str):
                pad_len = ord(pad_len)
            decrypted = decrypted[:-pad_len]

            # 跳过16字节随机数
            content = decrypted[16:]

            # 使用大端序读取长度
            xml_len = struct.unpack(">I", content[:4])[0]

            # 提取XML内容和corp_id
            xml_content = content[4:4 + xml_len]
            remaining = content[4 + xml_len:]
            from_corp_id = remaining.decode('utf-8').rstrip('\0')

            if from_corp_id != corp_id:
                return None

            return xml_content.decode('utf-8')
        except Exception as e:
            print(f"解密失败: {e}")
            return None

# 初始化加解密工具
wxcrypt = WXBizMsgCrypt(CONFIG['TOKEN'], CONFIG['ENCODING_AES_KEY'], CONFIG['CORP_ID'])

@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    #企业微信Webhook处理
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
        print(f"=== 处理POST消息 ===")
        # 获取参数
        msg_signature = request.args.get('msg_signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')

        print(f"POST参数: signature={msg_signature}, timestamp={timestamp}, nonce={nonce}")

        # 获取加密的消息体
        data = request.get_data()
        print(f"接收到的数据长度: {len(data)}")
        print(f"接收到的原始数据: {data}")
        if not data:
            print("ERROR: 没有接收到消息数据")
            return 'no data', 400
        # root = ET.fromstring(data)
        # encrypt = root.find('Encrypt').text

        # 解析XML
        try:
            root = ET.fromstring(data)
            encrypt = root.find('Encrypt').text
            print(f"加密消息: {encrypt[:50]}...")
        except Exception as e:
            print(f"ERROR: XML解析失败: {e}")
            return 'xml parse failed', 400

        # 验证签名
        signature = wxcrypt.sha1(CONFIG['TOKEN'], timestamp, nonce, encrypt)
        print(f"计算签名: {signature}")
        print(f"预期签名: {msg_signature}")

        if signature != msg_signature:
            print("ERROR: 签名验证失败")
            return 'signature check failed', 400

        print("✓ 签名验证成功")

        # 解密消息
        print("开始解密消息...")
        decrypted_msg = wxcrypt.decrypt(encrypt, CONFIG['CORP_ID'])
        if not decrypted_msg:
            print("ERROR: 解密失败")
            return 'decrypt failed', 400

        print(f"✓ 解密成功: {decrypted_msg}")

        # # 解析XML消息
        # msg_root = ET.fromstring(decrypted_msg)
        # msg_type = msg_root.find('MsgType').text

        # 解析XML消息
        try:
            msg_root = ET.fromstring(decrypted_msg)
            msg_type = msg_root.find('MsgType').text
            print(f"消息类型: {msg_type}")

            if msg_type == 'event':
                # 处理事件消息（企业微信客服）
                event = msg_root.find('Event').text
                print(f"事件类型: {event}")

                if event == 'kf_msg_or_event':
                    # 这是客服消息事件，需要通过客服API获取具体消息
                    token = msg_root.find('Token').text
                    open_kf_id = msg_root.find('OpenKfId').text
                    print(f"客服Token: {token}")
                    print(f"客服ID: {open_kf_id}")

                    # 调用企业微信客服API获取具体消息
                    handle_kf_message(token, open_kf_id)

            elif msg_type == 'text':
                # 处理文本消息
                from_user = msg_root.find('FromUserName').text
                content = msg_root.find('Content').text
                print(f"发送用户: {from_user}")
                print(f"消息内容: {content}")

                # 消息去重处理
                message_id = msg_root.find('MsgId').text
                if message_id in processed_messages:
                    print(f"重复消息，跳过处理: {message_id}")
                    return 'success'
                else:
                    # 添加到已处理消息集合
                    processed_messages.add(message_id)
                    if len(processed_messages) > MAX_PROCESSED_MESSAGES:
                        # 超过最大数量，移除最旧的消息
                        processed_messages.pop()

                # 调用Dify API获取回复
                print("准备调用Dify API...")
                reply = call_dify_api(content, from_user)
                print(f"Dify回复: {reply}")

                # 发送回复给企业微信
                print("准备发送回复到企业微信...")
                result = send_message_to_wechat(from_user, reply)
                print(f"发送结果: {result}")
            else:
                print(f"未处理的消息类型: {msg_type}")

        except Exception as e:
            print(f"ERROR: 消息解析失败: {e}")
            return 'message parse failed', 400

        return 'success'

        # if msg_type == 'text':
        #     # 处理文本消息
        #     from_user = msg_root.find('FromUserName').text
        #     content = msg_root.find('Content').text
        #
        #     # 调用Dify API获取回复
        #     reply = call_dify_api(content, from_user)
        #
        #     # 发送回复给企业微信
        #     send_message_to_wechat(from_user, reply)
        #
        # return 'success'

    except Exception as e:
        print(f"处理消息失败: {e}")
        import traceback
        traceback.print_exc()
        return 'error', 500

@app.route('/status', methods=['GET'])
def get_status():
    """获取消息处理状态"""
    return jsonify({
        "processed_messages_count": len(processed_messages),
        "max_processed_messages": MAX_PROCESSED_MESSAGES,
        "message_cursors": message_cursors,
        "recent_processed_messages": list(processed_messages)[-10:] if processed_messages else []
    })

@app.route('/clear_cache', methods=['POST'])
def clear_cache():
    """清空消息缓存"""
    global processed_messages, message_cursors
    processed_messages.clear()
    message_cursors.clear()
    return jsonify({
        "status": "success",
        "message": "消息缓存已清空"
    })

# @app.route('/test_dify', methods=['GET'])
# def test_dify():
#     """测试Dify API调用"""
#     try:
#         test_message = request.args.get('msg', '你好')
#         test_user = request.args.get('user', 'test_user')
#
#         print(f"测试Dify API调用: {test_message}")
#         reply = call_dify_api(test_message, test_user)
#
#         return jsonify({
#             "status": "success",
#             "test_message": test_message,
#             "reply": reply,
#             "dify_url": CONFIG['DIFY_API_BASE']
#         })
#     except Exception as e:
#         return jsonify({
#             "status": "error",
#             "error": str(e)
#         })

def call_dify_api(message, user_id):
    """调用Dify API获取回复"""
    try:
        url = f"{CONFIG['DIFY_API_BASE']}/chat-messages"

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

        print(f"调用Dify API URL: {url}")
        print(f"请求头: {headers}")
        print(f"请求数据: {data}")

        response = requests.post(url, headers=headers, json=data, timeout=30)

        print(f"响应状态码: {response.status_code}")
        print(f"响应内容: {response.text}")

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

def handle_kf_message(token, open_kf_id):
    """处理企业微信客服消息"""
    try:
        print(f"开始处理客服消息，token: {token}, open_kf_id: {open_kf_id}")

        # 获取access_token
        access_token = get_access_token()
        if not access_token:
            print("ERROR: 无法获取access_token")
            return False

        # 调用客服API获取消息
        url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}"

        # 使用cursor来避免重复获取消息
        cursor = message_cursors.get(open_kf_id, "")

        # 如果是第一次获取消息，只获取最新的少量消息
        if not cursor:
            print(f"首次获取客服消息，只处理最新消息")
            data = {
                "token": token,
                "limit": 10,  # 首次只获取最新的10条消息
                "voice_format": 0,
                "open_kfid": open_kf_id
            }
        else:
            data = {
                "cursor": cursor,
                "token": token,
                "limit": 100,
                "voice_format": 0,
                "open_kfid": open_kf_id
            }

        print(f"调用客服API URL: {url}")
        print(f"请求数据: {data}")

        response = requests.post(url, json=data)
        result = response.json()

        print(f"客服API响应: {result}")

        if result.get('errcode') == 0:
            msg_list = result.get('msg_list', [])
            next_cursor = result.get('next_cursor', "")

            # 更新cursor
            if next_cursor:
                message_cursors[open_kf_id] = next_cursor
                print(f"更新cursor: {next_cursor}")

            # 如果是首次获取且没有cursor，设置一个初始cursor避免重复处理历史消息
            elif not cursor and msg_list:
                # 使用最后一条消息的时间作为cursor的基础
                message_cursors[open_kf_id] = str(int(time.time() * 1000))
                print(f"设置初始cursor: {message_cursors[open_kf_id]}")

            # 只处理最新的消息（如果是首次获取，只处理最后一条）
            messages_to_process = msg_list
            if not cursor and msg_list:
                # 首次获取只处理最新的一条消息
                messages_to_process = msg_list[-1:]
                print(f"首次获取，只处理最新的一条消息")

            for msg in messages_to_process:
                if msg.get('msgtype') == 'text':
                    # 获取消息ID和时间戳进行去重
                    msg_id = msg.get('msgid', '')
                    send_time = msg.get('send_time', 0)
                    external_userid = msg.get('external_userid')
                    content = msg.get('text', {}).get('content', '')

                    # 检查消息时间，只处理最近5分钟内的消息
                    current_time = int(time.time())
                    if send_time > 0 and (current_time - send_time) > 300:  # 5分钟 = 300秒
                        print(f"跳过历史消息: 消息时间={send_time}, 当前时间={current_time}")
                        continue

                    # 检查是否已处理过此消息
                    unique_msg_id = f"kf_{msg_id}_{external_userid}_{send_time}"
                    if unique_msg_id in processed_messages:
                        print(f"重复客服消息，跳过处理: {unique_msg_id}")
                        continue

                    # 添加到已处理消息集合
                    processed_messages.add(unique_msg_id)
                    if len(processed_messages) > MAX_PROCESSED_MESSAGES:
                        # 超过最大数量，移除最旧的消息
                        processed_messages.pop()

                    print(f"处理客服文本消息: 用户={external_userid}, 内容={content}, 消息ID={msg_id}, 时间={send_time}")

                    # 调用Dify API获取回复
                    reply = call_dify_api(content, external_userid)
                    print(f"Dify回复: {reply}")

                    # 发送回复给客服
                    send_kf_message(open_kf_id, external_userid, reply)

        return True

    except Exception as e:
        print(f"处理客服消息失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def send_kf_message(open_kf_id, external_userid, content):
    """发送消息到企业微信客服"""
    try:
        # 获取access_token
        access_token = get_access_token()
        if not access_token:
            return False

        url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token={access_token}"

        data = {
            "touser": external_userid,
            "open_kfid": open_kf_id,
            "msgid": str(int(time.time() * 1000)),
            "msgtype": "text",
            "text": {
                "content": content
            }
        }

        print(f"发送客服消息: {data}")
        response = requests.post(url, json=data)
        result = response.json()

        print(f"发送客服消息结果: {result}")

        if result.get('errcode') == 0:
            print(f"客服消息发送成功: {content}")
            return True
        else:
            print(f"客服消息发送失败: {result}")
            return False

    except Exception as e:
        print(f"发送客服消息异常: {e}")
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


    # 使用adhoc SSL（自动生成自签名证书，仅用于开发）
    app.run(host='0.0.0.0', port=11850, debug=True)
