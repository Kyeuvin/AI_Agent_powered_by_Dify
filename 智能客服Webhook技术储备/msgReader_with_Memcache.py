#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
企业微信消息读取器
功能：
1. 读取企业微信推送的消息
2. 处理接收到的消息
使用 Memcache 存储缓存数据
"""

import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from flask import Flask, request
import requests
import hashlib
import base64
import struct
from Crypto.Cipher import AES
from pymemcache.client import base

app = Flask(__name__)

# Memcache 配置
MEMCACHE_CONFIG = {
    'host': 'localhost',  # Memcache 服务器地址
    'port': 11211,        # Memcache 服务器端口
    'connect_timeout': 5,
    'timeout': 5
}

# 初始化 Memcache 客户端
try:
    mc = base.Client((MEMCACHE_CONFIG['host'], MEMCACHE_CONFIG['port']),
                     connect_timeout=MEMCACHE_CONFIG['connect_timeout'],
                     timeout=MEMCACHE_CONFIG['timeout'])
    # 测试连接
    mc.set('test_connection', 'ok', expire=10)
    test_result = mc.get('test_connection')
    if test_result == b'ok':
        print("✅ Memcache 连接成功")
    else:
        print("⚠️ Memcache 连接测试失败")
except Exception as e:
    print(f"❌ Memcache 连接失败: {e}")
    mc = None

# 配置信息 - 请根据您的实际情况修改
CONFIG = {
    # 企业微信配置
    'CORP_ID': 'ww5a90dfd630815d26',
    'AGENT_ID': '1000004',
    'CORP_SECRET': 'kJoffzGOUP4KseynjfkESWyxHsLUSJN_mmP4QmPDb2Y',
    'TOKEN': 'gbiOBjx9IeIKo',
    'ENCODING_AES_KEY': '5V8ppBRuFTfT7kTlPgYiqXrISLkxYeBWjFbhCzL2NIC',
}

# Memcache 键名常量
CACHE_KEYS = {
    'ACCESS_TOKEN': 'wechat_access_token',
    'CURSOR_PREFIX': 'wechat_cursor_',
    'PROCESSED_MSG_PREFIX': 'wechat_processed_',
    'REQUEST_PREFIX': 'wechat_request_'
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
                print(f"⚠️  Corp ID不匹配: 期望={corp_id}, 实际={from_corp_id}")
                return None

            return xml_content.decode('utf-8')
        except Exception as e:
            print(f"❌ 解密失败: {e}")
            return None

# 初始化加解密工具
wxcrypt = WXBizMsgCrypt(CONFIG['TOKEN'], CONFIG['ENCODING_AES_KEY'], CONFIG['CORP_ID'])

def cache_set(key, value, expire=7200):
    """设置缓存"""
    if mc:
        try:
            if isinstance(value, dict) or isinstance(value, list):
                value = json.dumps(value)
            mc.set(key.encode('utf-8'), value, expire=expire)
            return True
        except Exception as e:
            print(f"❌ 缓存设置失败 {key}: {e}")
    return False

def cache_get(key):
    """获取缓存"""
    if mc:
        try:
            result = mc.get(key.encode('utf-8'))
            if result:
                result = result.decode('utf-8')
                # 尝试解析JSON
                try:
                    return json.loads(result)
                except:
                    return result
        except Exception as e:
            print(f"❌ 缓存获取失败 {key}: {e}")
    return None

def cache_delete(key):
    """删除缓存"""
    if mc:
        try:
            mc.delete(key.encode('utf-8'))
            return True
        except Exception as e:
            print(f"❌ 缓存删除失败 {key}: {e}")
    return False

def cache_exists(key):
    """检查缓存是否存在"""
    result = cache_get(key)
    return result is not None

def format_timestamp(timestamp):
    """格式化时间戳"""
    if isinstance(timestamp, str):
        timestamp = int(timestamp)
    if timestamp > 1000000000000:  # 毫秒时间戳
        timestamp = timestamp / 1000
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def get_access_token():
    """获取企业微信access_token（使用Memcache缓存）"""
    try:
        # 从缓存获取
        token_data = cache_get(CACHE_KEYS['ACCESS_TOKEN'])

        if token_data and isinstance(token_data, dict):
            current_time = time.time()
            if current_time < token_data.get('expires_at', 0) - 300:  # 提前5分钟刷新
                return token_data.get('token')

        # 重新获取
        url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CONFIG['CORP_ID']}&corpsecret={CONFIG['CORP_SECRET']}"

        response = requests.get(url, timeout=10)
        result = response.json()

        if result.get('errcode') == 0:
            token = result.get('access_token')
            expires_in = result.get('expires_in', 7200)
            current_time = time.time()

            # 保存到缓存
            token_data = {
                "token": token,
                "expires_at": current_time + expires_in
            }
            cache_set(CACHE_KEYS['ACCESS_TOKEN'], token_data, expire=expires_in - 300)

            print(f"✅ 获取新的access_token，有效期至: {format_timestamp(token_data['expires_at'])}")
            return token
        else:
            print(f"❌ 获取access_token失败: {result}")
            return None

    except Exception as e:
        print(f"❌ 获取access_token异常: {e}")
        return None

def get_message_cursor(open_kf_id):
    """获取消息游标"""
    cursor_key = f"{CACHE_KEYS['CURSOR_PREFIX']}{open_kf_id}"
    return cache_get(cursor_key) or ""

def set_message_cursor(open_kf_id, cursor):
    """设置消息游标"""
    cursor_key = f"{CACHE_KEYS['CURSOR_PREFIX']}{open_kf_id}"
    return cache_set(cursor_key, cursor, expire=86400 * 7)  # 7天过期

def is_message_processed(unique_msg_id):
    """检查消息是否已处理"""
    msg_key = f"{CACHE_KEYS['PROCESSED_MSG_PREFIX']}{unique_msg_id}"
    return cache_exists(msg_key)

def mark_message_processed(unique_msg_id):
    """标记消息已处理"""
    msg_key = f"{CACHE_KEYS['PROCESSED_MSG_PREFIX']}{unique_msg_id}"
    return cache_set(msg_key, "1", expire=86400)  # 24小时过期

def is_request_processed(request_id):
    """检查请求是否已处理"""
    req_key = f"{CACHE_KEYS['REQUEST_PREFIX']}{request_id}"
    return cache_exists(req_key)

def mark_request_processed(request_id):
    """标记请求已处理"""
    req_key = f"{CACHE_KEYS['REQUEST_PREFIX']}{request_id}"
    return cache_set(req_key, "1", expire=300)  # 5分钟过期

@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    """企业微信Webhook处理主入口"""
    if request.method == 'GET':
        return verify_url()
    elif request.method == 'POST':
        return handle_message()

def verify_url():
    """验证URL有效性"""
    try:
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
            else:
                print(f"❌ 解密echostr失败")
        else:
            print(f"❌ 签名验证失败: 计算={signature}, 期望={msg_signature}")

        return 'fail', 400
    except Exception as e:
        print(f"❌ URL验证异常: {e}")
        return 'error', 400

def handle_message():
    """处理接收到的消息"""
    try:
        # 获取参数
        msg_signature = request.args.get('msg_signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')

        # 请求去重检查
        request_id = f"{msg_signature}_{timestamp}_{nonce}"
        if is_request_processed(request_id):
            print(f"⚠️ 重复的Webhook请求，已处理过: {request_id}")
            return 'success'

        # 标记请求为已处理
        mark_request_processed(request_id)

        # 获取加密的消息体
        data = request.get_data()

        if not data:
            print("❌ 没有接收到消息数据")
            return 'no data', 400

        # 解析XML
        try:
            root = ET.fromstring(data)
            encrypt = root.find('Encrypt').text
        except Exception as e:
            print(f"❌ XML解析失败: {e}")
            return 'xml parse failed', 400

        # 验证签名
        signature = wxcrypt.sha1(CONFIG['TOKEN'], timestamp, nonce, encrypt)

        if signature != msg_signature:
            print(f"❌ 签名验证失败: 计算={signature}, 期望={msg_signature}")
            return 'signature check failed', 400

        # 解密消息
        decrypted_msg = wxcrypt.decrypt(encrypt, CONFIG['CORP_ID'])
        if not decrypted_msg:
            print("❌ 解密失败")
            return 'decrypt failed', 400

        # 解析并处理消息
        process_decrypted_message(decrypted_msg)

        return 'success'

    except Exception as e:
        print(f"❌ 处理消息失败: {e}")
        import traceback
        traceback.print_exc()
        return 'error', 500

def process_decrypted_message(decrypted_msg):
    """处理解密后的消息"""
    try:
        msg_root = ET.fromstring(decrypted_msg)
        msg_type = msg_root.find('MsgType').text

        if msg_type == 'event':
            # 处理事件消息（企业微信客服）
            event = msg_root.find('Event').text
            print(f"🎯 事件类型: {event}")

            if event == 'kf_msg_or_event':
                # 客服消息事件
                token = msg_root.find('Token').text
                open_kf_id = msg_root.find('OpenKfId').text

                # 获取具体的客服消息
                fetch_and_process_kf_messages(token, open_kf_id)

        elif msg_type == 'text':
            # 处理普通文本消息
            from_user = msg_root.find('FromUserName').text
            content = msg_root.find('Content').text
            message_id = msg_root.find('MsgId').text
            create_time = msg_root.find('CreateTime').text

            print(f"💬 普通文本消息:")
            print(f"   发送用户: {from_user}")
            print(f"   消息内容: {content}")
            print(f"   消息ID: {message_id}")
            print(f"   发送时间: {format_timestamp(create_time)}")
            print(f"   时间戳: {create_time}")

        else:
            print(f"❓ 未处理的消息类型: {msg_type}")
            # 打印完整的XML内容以便调试
            print(f"📄 完整消息内容: {decrypted_msg}")

    except Exception as e:
        print(f"❌ 消息解析失败: {e}")
        import traceback
        traceback.print_exc()

def fetch_and_process_kf_messages(token, open_kf_id):
    """获取并处理企业微信客服消息"""
    try:
        access_token = get_access_token()
        if not access_token:
            print("❌ 无法获取access_token")
            return

        # 调用客服API获取消息
        url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}"

        # 从缓存获取cursor
        cursor = get_message_cursor(open_kf_id)

        # 根据是否有cursor来决定获取消息的策略
        if not cursor:
            # 首次获取策略：利用has_more参数获取最新消息
            data = {
                "token": token,
                "limit": 1,  # 首次只获取1条消息
                "voice_format": 0,
                "open_kfid": open_kf_id
            }
        else:
            # 有cursor，正常增量获取
            data = {
                "cursor": cursor,
                "token": token,
                "limit": 100,
                "voice_format": 0,
                "open_kfid": open_kf_id
            }

        response = requests.post(url, json=data, timeout=10)
        result = response.json()

        print(f"📨 客服API响应: 状态码: {response.status_code} 错误码: {result.get('errcode', 'N/A')} 错误信息: {result.get('errmsg', 'N/A')}")

        if result.get('errcode') == 0:
            msg_list = result.get('msg_list', [])
            next_cursor = result.get('next_cursor', "")
            has_more = result.get('has_more', 0)

            print(f"📊 消息统计: 消息数量: {len(msg_list)} 是否还有更多: {'是' if has_more else '否'}")

            # 处理首次获取的特殊逻辑
            if not cursor and msg_list:
                if has_more == 1:
                    print("⚠️ 检测到还有更多消息，当前获取的可能是历史消息")
                    # 策略：不断获取消息直到has_more为0，然后取最后一批的最新消息
                    latest_messages, next_cursor = await_get_latest_messages(token, open_kf_id, access_token)
                    if latest_messages:
                        messages_to_process = [latest_messages[0]]  # 取最新的一条
                        print(f"✅ 成功获取最新消息，时间: {format_timestamp(latest_messages[0].get('send_time', 0))}")
                    else:
                        messages_to_process = []
                else:
                    print("✅ 没有更多消息，当前消息就是最新的")
                    messages_to_process = msg_list

                # 设置cursor到缓存
                if next_cursor:
                    set_message_cursor(open_kf_id, next_cursor)
                    print(f"🔄 设置Cursor为: {next_cursor}")
                else:
                    # 如果没有next_cursor，使用当前时间戳作为cursor
                    initial_cursor = str(int(time.time() * 1000))
                    set_message_cursor(open_kf_id, initial_cursor)

            else:
                # 正常增量获取，处理所有消息
                messages_to_process = msg_list

                # 更新cursor到缓存
                if next_cursor:
                    old_cursor = get_message_cursor(open_kf_id)
                    set_message_cursor(open_kf_id, next_cursor)

            # 处理消息
            if messages_to_process:
                print(f"📝 准备处理 {len(messages_to_process)} 条消息")
                for i, msg in enumerate(messages_to_process, 1):
                    process_single_kf_message(msg, open_kf_id)
            else:
                print("📭 没有需要处理的消息")

        else:
            print(f"❌ 客服API调用失败: {result}")

    except Exception as e:
        print(f"❌ 获取客服消息失败: {e}")
        import traceback
        traceback.print_exc()

def process_single_kf_message(msg, open_kf_id):
    """处理单条客服消息"""
    try:
        # 基本信息
        msgtype = msg.get('msgtype', '')
        msgid = msg.get('msgid', '')
        send_time = msg.get('send_time', 0)
        origin = msg.get('origin', 0)
        external_userid = msg.get('external_userid', '')

        print(f"📨 消息基本信息: 消息ID: {msgid} 消息类型: {msgtype} 发送时间: {format_timestamp(send_time)} 发送方: {'用户' if origin == 3 else '系统推送' if origin == 4 else f'未知({origin})'}")

        # 构造唯一消息ID用于去重
        unique_msg_id = f"kf_{msgid}_{external_userid}_{send_time}"

        if is_message_processed(unique_msg_id):
            print(f"⚠️ 重复消息，已处理过")
            return

        # 根据消息类型处理具体内容
        if msgtype == 'text':
            content = msg.get('text', {}).get('content', '')
            print(f"💬 文本内容: {content}")

        elif msgtype == 'image':
            image_info = msg.get('image', {})
            print(f"🖼️ 图片消息:")
            print(f"   媒体ID: {image_info.get('media_id', '')}")

        elif msgtype == 'voice':
            voice_info = msg.get('voice', {})
            print(f"🎵 语音消息:")
            print(f"   媒体ID: {voice_info.get('media_id', '')}")

        elif msgtype == 'file':
            file_info = msg.get('file', {})
            print(f"📎 文件消息:")
            print(f"   文件名: {file_info.get('filename', '')}")
            print(f"   媒体ID: {file_info.get('media_id', '')}")

        else:
            print(f"❓ 其他类型消息:")
            print(f"   完整内容: {json.dumps(msg, indent=2, ensure_ascii=False)}")

        # 标记为已处理
        mark_message_processed(unique_msg_id)
        print(f"✅ 标记为已处理")

    except Exception as e:
        print(f"❌ 处理单条消息失败: {e}")
        import traceback
        traceback.print_exc()

def await_get_latest_messages(token, open_kf_id, access_token):
    """跳跃策略获取最新消息"""
    try:
        print("🔄 开始跳跃策略获取最新消息...")
        url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}"

        current_cursor = ""
        all_messages = []
        max_iterations = 10  # 防止无限循环
        iteration = 0

        while iteration < max_iterations:
            iteration += 1
            print(f"   第{iteration}次跳跃...")

            data = {
                "token": token,
                "limit": 1000,  # 大批量获取
                "voice_format": 0,
                "open_kfid": open_kf_id
            }

            if current_cursor:
                data["cursor"] = current_cursor

            response = requests.post(url, json=data, timeout=10)
            result = response.json()

            if result.get('errcode') != 0:
                print(f"   ❌ 跳跃失败: {result}")
                break

            msg_list = result.get('msg_list', [])
            next_cursor = result.get('next_cursor', "")
            has_more = result.get('has_more', 0)
            current_cursor = next_cursor
            print(f"   获取到{len(msg_list)}条消息，has_more={has_more}")

            if msg_list:
                all_messages.extend(msg_list)

            if has_more == 0:
                break

            if not next_cursor:
                print("   ⚠️ 没有next_cursor，停止跳跃")
                break

        if all_messages:
            # 按时间排序，返回最新的消息
            sorted_messages = sorted(all_messages, key=lambda x: x.get('send_time', 0), reverse=True)
            print(f"   📊 跳跃完成，共获取{len(all_messages)}条消息，最新消息时间: {format_timestamp(sorted_messages[0].get('send_time', 0))}")
            return sorted_messages, current_cursor
        else:
            print("   📭 跳跃过程中没有获取到任何消息")
            return [], current_cursor

    except Exception as e:
        print(f"   ❌ 跳跃策略执行失败: {e}")
        return [], ""

@app.route('/status', methods=['GET'])
def get_status():
    """获取当前状态"""
    if not mc:
        return {"error": "Memcache not available"}

    try:
        # 获取统计信息（这里只是示例，实际统计需要遍历所有key）
        status = {
            "memcache_status": "connected",
            "cache_keys": {
                "access_token": bool(cache_get(CACHE_KEYS['ACCESS_TOKEN'])),
            }
        }
        return status
    except Exception as e:
        return {"error": f"Status check failed: {e}"}

@app.route('/clear', methods=['POST'])
def clear_data():
    """清空所有数据"""
    if not mc:
        return {"error": "Memcache not available"}

    try:
        # 清空access_token
        cache_delete(CACHE_KEYS['ACCESS_TOKEN'])

        # 注意：这里无法直接清空所有带前缀的key，需要Memcache支持或者记录所有key
        print("✅ 主要缓存数据已清空")
        return {"status": "success", "message": "缓存数据已清空"}
    except Exception as e:
        return {"error": f"Clear failed: {e}"}

if __name__ == '__main__':
    print("🚀 服务启动中...")
    app.run(host='0.0.0.0', port=11850, debug=True)