from flask import Flask, request
import requests
import hashlib
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES
import base64
import struct
import time

# 尝试导入memcache，如果失败则使用字典作为备用缓存
try:
    import pymemcache
    memcache_client = pymemcache.Client(('server', 11211))
    MEMCACHE_AVAILABLE = True
    print("Memcache连接成功")
except ImportError:
    print("Memcache模块未安装，使用内存缓存")
    memcache_client = None
    MEMCACHE_AVAILABLE = False
except Exception as e:
    print(f"Memcache连接失败: {e}，使用内存缓存")
    memcache_client = None
    MEMCACHE_AVAILABLE = False

# 内存缓存字典（当memcache不可用时使用）
memory_cache = {}

class CacheManager:
    """缓存管理器，兼容memcache和内存缓存"""

    def __init__(self):
        self.memory_cache = {}

    def get(self, key):
        """获取缓存值"""
        if MEMCACHE_AVAILABLE and memcache_client:
            try:
                return memcache_client.get(key)
            except Exception as e:
                print(f"Memcache get失败: {e}")
                return self.memory_cache.get(key)
        else:
            return self.memory_cache.get(key)

    def set(self, key, value, time=0):
        """设置缓存值"""
        if MEMCACHE_AVAILABLE and memcache_client:
            try:
                return memcache_client.set(key, value, time=time)
            except Exception as e:
                print(f"Memcache set失败: {e}")
                self.memory_cache[key] = value
                return True
        else:
            self.memory_cache[key] = value
            return True

    def delete(self, key):
        """删除缓存值"""
        if MEMCACHE_AVAILABLE and memcache_client:
            try:
                return memcache_client.delete(key)
            except Exception as e:
                print(f"Memcache delete失败: {e}")
                return self.memory_cache.pop(key, None) is not None
        else:
            return self.memory_cache.pop(key, None) is not None

# 创建缓存管理器实例
cache_manager = CacheManager()

app = Flask(__name__)

CONFIG = {
    #企业微信配置
    'CORP_ID': 'ww5a90dfd630815d26',
    'AGENT_ID': '1000004',
    'CORP_SECRET': 'kJoffzGOUP4KseynjfkESWyxHsLUSJN_mmP4QmPDb2Y',
    'TOKEN': 'gbiOBjx9IeIKo',  # 企业微信应用的Token
    'ENCODING_AES_KEY': '5V8ppBRuFTfT7kTlPgYiqXrISLkxYeBWjFbhCzL2NIC',  # 企业微信应用的EncodingAESKey

    # Dify配置
    'DIFY_API_BASE': 'http://192.168.1.18:8010/v1',  # 您的Dify服务器内网地址
    'DIFY_API_KEY': 'app-GgOmbbzRXwobVRxcG901yIAr',  # Dify应用的API密钥
}

class WXMsgCrypt:
    #企业微信消息加解密工具类

    def __init__(self, token, encoding_aes_key, corp_id):
        self.token = token
        self.encoding_aes_key = encoding_aes_key
        self.corp_id = corp_id

    def sha1(self, *args):
        #计算SHA1签名
        sha1 = hashlib.sha1()
        for arg in args:
            sha1.update(arg.encode('utf-8'))
        return sha1.hexdigest()

    def decrypt(self, encrypt_msg, corp_id):
        """解密企业微信消息"""
        try:
            # Base64解码
            key_with_padding = self.encoding_aes_key + '=' * (4 - len(self.encoding_aes_key) % 4)
            key = base64.b64decode(key_with_padding)
            encrypt_msg_with_padding = encrypt_msg + '=' * (4 - len(encrypt_msg) % 4)
            encrypt_msg = base64.b64decode(encrypt_msg_with_padding)

            #AES解密
            iv = key[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypt_msg)

            # 去除PKCS7填充
            pad_len = decrypted[-1]
            if isinstance(pad_len, str):
                pad_len = ord(pad_len)
            decrypted = decrypted[:-pad_len]

            #跳过16字节随机数
            content = decrypted[16:]

            # 提取消息内容(大端序读取长度)
            xml_len = struct.unpack(">I", content[:4])[0]
            xml_content = decrypted[4:4 + xml_len]
            from_corp_id = decrypted[4 + xml_len:].decode('utf-8').rstrip('\0')

            if from_corp_id != corp_id:
                print(f"Corp ID不匹配!: {from_corp_id} != {corp_id}")
                return None
            return xml_content.decode('utf-8')
        except Exception as e:
            print(f"解密失败: {e}")
            return None

#初始化加解密工具
wxcrypt = WXMsgCrypt(CONFIG['TOKEN'], CONFIG['ENCODING_AES_KEY'], CONFIG['CORP_ID'])

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

def handle_message(token, open_kf_id):
    """处理企业微信客服消息 - 使用官方cursor机制"""
    try:
        msg_signature = request.args.get('msg_signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')

        # 获取加密的消息体
        data = request.get_data()
        if not data:
            print("无消息体")
            return 'no data', 400

        try:
            root = ET.fromstring(data)
            encrypt_msg = root.find('Encrypt').text
        except Exception as e:
            print(f"解析XML失败: {e}")
            return 'invalid xml', 400

        # 验证签名
        signature = wxcrypt.sha1(CONFIG['TOKEN'], timestamp, nonce, encrypt_msg)

        if signature != msg_signature:
            print("签名验证失败")
            return 'invalid signature', 400

        # 解密消息
        decrypted_xml = wxcrypt.decrypt(encrypt_msg, CONFIG['CORP_ID'])
        if not decrypted_xml:
            print("消息解密失败")
            return 'decryption failed', 400
        print(f"解密后的消息: {decrypted_xml}")

        try:
            msg_root = ET.fromstring(decrypted_xml)
            to_user = msg_root.find('ToUserName').text

            event = msg_root.find('Event').text
            token = msg_root.find('Token').text
            open_kf_id = msg_root.find('OpenKfid').text

            try:
                access_token = get_access_token()
                if not access_token:
                    print("ERROR: 无法获取access_token")
                    return False

                # 获取上次处理的cursor
                cursor_key = f"kf_cursor_{open_kf_id}"
                last_cursor = cache_manager.get(cursor_key) or ""

                print(f"上次cursor: {last_cursor}")

                url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}"

                # 构建请求数据
                data = {
                    "token": token,
                    "limit": 1000,
                    "voice_format": 0,
                    "open_kfid": open_kf_id
                }

                # 只有存在cursor时才添加，这样可以避免重复获取历史消息
                if last_cursor:
                    data["cursor"] = last_cursor
                    print(f"使用cursor: {last_cursor}")
                else:
                    print("首次获取消息，不使用cursor")

                print(f"调用客服API URL: {url}")
                print(f"请求数据: {data}")

                response = requests.post(url, json=data)
                result = response.json()

                # 检查是否token过期，如果过期则重新获取并重试一次
                if result.get('errcode') in [40014, 42001]:
                    print("access_token过期，清除缓存并重新获取")
                    cache_manager.delete("wechat_access_token")

                    # 重新获取token并重试
                    access_token = get_access_token()
                    if access_token:
                        url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}"
                        response = requests.post(url, json=data)
                        result = response.json()

                print(f"客服API响应: {result}")

                if result.get('errcode') == 0:
                    msg_list = result.get('msg_list', [])
                    next_cursor = result.get('next_cursor', '')
                    has_more = result.get('has_more', 0)

                    print(f"获取到 {len(msg_list)} 条消息")
                    print(f"next_cursor: {next_cursor}")
                    print(f"has_more: {has_more}")

                    # 处理消息
                    processed_count = 0
                    for msg in msg_list:
                        if process_single_message(msg, open_kf_id):
                            processed_count += 1

                    print(f"实际处理了 {processed_count} 条新消息")

                    # 重要：只有成功处理了消息才更新cursor
                    if next_cursor and len(msg_list) > 0:
                        cache_manager.set(cursor_key, next_cursor, time=86400)  # 24小时过期
                        print(f"更新cursor为: {next_cursor}")

                    # 如果还有更多消息，递归处理
                    if has_more == 1 and next_cursor:
                        print("还有更多消息，继续获取...")
                        time.sleep(0.1)  # 短暂延迟避免频率限制
                        return handle_message()

                return True

            except Exception as e:
                print(f"处理客服消息失败: {e}")
                import traceback
                traceback.print_exc()
                return False

        except Exception as e:
            print(f"解析解密后的XML失败: {e}")
            return 'invalid decrypted xml', 400
        return 'success'
    except Exception as e:
        print(f"处理消息异常: {e}")
        return 'error', 500

    # try:
    #     access_token = get_access_token()
    #     if not access_token:
    #         print("ERROR: 无法获取access_token")
    #         return False
    #
    #     # 获取上次处理的cursor
    #     cursor_key = f"kf_cursor_{open_kf_id}"
    #     last_cursor = cache_manager.get(cursor_key) or ""
    #
    #     print(f"上次cursor: {last_cursor}")
    #
    #     url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}"
    #
    #     # 构建请求数据
    #     data = {
    #         "token": token,
    #         "limit": 1000,
    #         "voice_format": 0,
    #         "open_kfid": open_kf_id
    #     }
    #
    #     # 只有存在cursor时才添加，这样可以避免重复获取历史消息
    #     if last_cursor:
    #         data["cursor"] = last_cursor
    #         print(f"使用cursor: {last_cursor}")
    #     else:
    #         print("首次获取消息，不使用cursor")
    #
    #     print(f"调用客服API URL: {url}")
    #     print(f"请求数据: {data}")
    #
    #     response = requests.post(url, json=data)
    #     result = response.json()
    #
    #     # 检查是否token过期，如果过期则重新获取并重试一次
    #     if result.get('errcode') in [40014, 42001]:
    #         print("access_token过期，清除缓存并重新获取")
    #         cache_manager.delete("wechat_access_token")
    #
    #         # 重新获取token并重试
    #         access_token = get_access_token()
    #         if access_token:
    #             url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}"
    #             response = requests.post(url, json=data)
    #             result = response.json()
    #
    #     print(f"客服API响应: {result}")
    #
    #     if result.get('errcode') == 0:
    #         msg_list = result.get('msg_list', [])
    #         next_cursor = result.get('next_cursor', '')
    #         has_more = result.get('has_more', 0)
    #
    #         print(f"获取到 {len(msg_list)} 条消息")
    #         print(f"next_cursor: {next_cursor}")
    #         print(f"has_more: {has_more}")
    #
    #         # 处理消息
    #         processed_count = 0
    #         for msg in msg_list:
    #             if process_single_message(msg, open_kf_id):
    #                 processed_count += 1
    #
    #         print(f"实际处理了 {processed_count} 条新消息")
    #
    #         # 重要：只有成功处理了消息才更新cursor
    #         if next_cursor and len(msg_list) > 0:
    #             cache_manager.set(cursor_key, next_cursor, time=86400)  # 24小时过期
    #             print(f"更新cursor为: {next_cursor}")
    #
    #         # 如果还有更多消息，递归处理
    #         if has_more == 1 and next_cursor:
    #             print("还有更多消息，继续获取...")
    #             time.sleep(0.1)  # 短暂延迟避免频率限制
    #             return handle_message(token, open_kf_id)
    #
    #     return True
    #
    # except Exception as e:
    #     print(f"处理客服消息失败: {e}")
    #     import traceback
    #     traceback.print_exc()
    #     return False


def process_single_message(msg, open_kf_id):
    """处理单条消息"""
    try:
        msg_type = msg.get('msgtype')
        origin = msg.get('origin', 0)  # 0-系统消息，3-客户消息，4-客服消息

        # 只处理客户发送的文本消息
        if msg_type != 'text' or origin != 3:
            return False

        msgid = msg.get('msgid', '')
        external_userid = msg.get('external_userid', '')
        send_time = msg.get('send_time', 0)
        content = msg.get('text', {}).get('content', '')

        if not msgid or not external_userid or not content:
            print(f"消息信息不完整，跳过: msgid={msgid}, user={external_userid}")
            return False

        # 使用官方推荐的唯一标识：msgid
        if is_message_processed(msgid):
            print(f"消息已处理，跳过: msgid={msgid}")
            return False

        print(f"处理新消息: user={external_userid}, content={content}, msgid={msgid}")

        # 调用Dify API获取回复
        reply = call_dify_api(content, external_userid)
        if not reply:
            print(f"Dify API调用失败，跳过发送")
            return False

        print(f"Dify回复: {reply}")

        # 发送回复
        if send_kf_message_with_limit(open_kf_id, external_userid, reply):
            # 只有成功发送后才标记为已处理
            mark_message_processed(msgid)
            return True
        else:
            print(f"消息发送失败: msgid={msgid}")
            return False

    except Exception as e:
        print(f"处理单条消息失败: {e}")
        return False


def is_message_processed(msgid):
    """检查消息是否已处理"""
    key = f"processed_msg_{msgid}"
    return cache_manager.get(key) is not None


def mark_message_processed(msgid):
    """标记消息为已处理"""
    key = f"processed_msg_{msgid}"
    # 设置过期时间为24小时，避免内存占用过多
    cache_manager.set(key, 1, time=86400)


def send_kf_message_with_limit(open_kf_id, external_userid, content):
    """带频率限制的消息发送"""
    try:
        # 检查发送频率
        rate_key = f"rate_limit_{external_userid}"
        current_time = int(time.time())

        # 获取最近发送记录
        last_sends = cache_manager.get(rate_key) or []

        # 清理1分钟前的记录
        recent_sends = [t for t in last_sends if current_time - t < 60]

        # 检查是否超过频率限制（每分钟最多3条）
        if len(recent_sends) >= 3:
            print(f"用户 {external_userid} 发送频率限制，跳过")
            return False

        # 发送消息
        access_token = get_access_token()
        if not access_token:
            return False

        url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token={access_token}"

        data = {
            "touser": external_userid,
            "open_kfid": open_kf_id,
            "msgid": str(int(time.time() * 1000)),
            "msgtype": "text",
            "text": {"content": content}
        }

        print(f"发送客服消息: {data}")

        response = requests.post(url, json=data, timeout=10)
        result = response.json()

        # 检查是否token过期，如果过期则重新获取并重试一次
        if result.get('errcode') in [40014, 42001]:
            print("access_token过期，清除缓存并重新获取")
            cache_manager.delete("wechat_access_token")

            # 重新获取token并重试
            access_token = get_access_token()
            if access_token:
                url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token={access_token}"
                response = requests.post(url, json=data, timeout=10)
                result = response.json()

        print(f"发送结果: {result}")

        if result.get('errcode') == 0:
            # 记录发送时间
            recent_sends.append(current_time)
            cache_manager.set(rate_key, recent_sends, time=3600)
            print(f"消息发送成功: {content[:50]}...")
            return True
        elif result.get('errcode') == 95001:
            print(f"频率限制错误95001，等待重试")
            time.sleep(2)
            return False
        else:
            print(f"发送失败: {result}")
            return False

    except Exception as e:
        print(f"发送消息异常: {e}")
        return False

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

        # 检查是否token过期，如果过期则重新获取并重试一次
        if result.get('errcode') in [40014, 42001]:
            print("access_token过期，清除缓存并重新获取")
            cache_manager.delete("wechat_access_token")

            # 重新获取token并重试
            access_token = get_access_token()
            if access_token:
                url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={access_token}"
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
    """获取企业微信access_token，使用缓存"""
    cache_key = "wechat_access_token"

    try:
        # 首先尝试从缓存获取token
        cached_token = cache_manager.get(cache_key)
        if cached_token:
            print("从缓存获取到access_token")
            return cached_token

        print("缓存中无有效token，开始获取新token")

        # 从企业微信API获取新token
        url = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
        params = {
            'corpid': CONFIG['CORP_ID'],
            'corpsecret': CONFIG['CORP_SECRET']
        }

        response = requests.get(url, params=params)
        result = response.json()

        if result.get('errcode') == 0:
            access_token = result.get('access_token')
            expires_in = result.get('expires_in', 7200)  # 默认7200秒

            # 将token存储到缓存，设置过期时间为获取到的时间减去5分钟作为缓冲
            cache_expire_time = max(expires_in - 300, 60)  # 至少缓存60秒

            cache_manager.set(cache_key, access_token, time=cache_expire_time)
            print(f"access_token已存储到缓存，缓存时间: {cache_expire_time}秒")

            return access_token
        else:
            print(f"获取access_token失败: {result}")
            return None

    except Exception as e:
        print(f"获取access_token异常: {e}")
        return None

def check_and_refresh_access_token(access_token):
    """检查access_token是否有效，如果无效则刷新"""
    try:
        # 使用一个简单的API调用来检查token是否有效
        test_url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?access_token={access_token}"
        response = requests.get(test_url, timeout=5)
        result = response.json()

        # 如果返回错误码40014（access_token无效）或42001（access_token过期）
        if result.get('errcode') in [40014, 42001]:
            print("access_token已过期，清除缓存并重新获取")
            cache_manager.delete("wechat_access_token")
            return get_access_token()

        return access_token

    except Exception as e:
        print(f"检查access_token异常: {e}")
        return access_token

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=11850, debug=True)
