from flask import Flask, request
import hashlib
import base64
from Crypto.Cipher import AES
import struct
import logging
import traceback

app = Flask(__name__)

# 配置详细日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 企业微信配置（请替换为您的实际配置）
TOKEN = "gbiOBjx9IeIKo"
ENCODING_AES_KEY = "5V8ppBRuFTfT7kTlPgYiqXrISLkxYeBWjFbhCzL2NIC"
CORP_ID = "ww5a90dfd630815d26"


def decrypt_msg(encrypt_msg, encoding_aes_key, corp_id):
    """解密企业微信消息"""
    try:
        logger.info(f"开始解密消息，encrypt_msg长度: {len(encrypt_msg)}")
        logger.debug(f"原始encrypt_msg: {encrypt_msg[:50]}...")

        # 补齐Base64填充
        key_with_padding = encoding_aes_key + "=" * (4 - len(encoding_aes_key) % 4)
        key = base64.b64decode(key_with_padding)
        logger.debug(f"解密密钥长度: {len(key)}")

        # 补齐Base64填充
        msg_with_padding = encrypt_msg + "=" * (4 - len(encrypt_msg) % 4)
        encrypt_msg_bytes = base64.b64decode(msg_with_padding)
        logger.debug(f"加密消息字节长度: {len(encrypt_msg_bytes)}")

        # AES解密
        iv = key[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypt_msg_bytes)
        logger.debug(f"解密后数据长度: {len(decrypted)}")

        # 提取消息内容
        content = decrypted[16:]
        xml_len = struct.unpack("I", content[:4])[0]
        logger.debug(f"XML内容长度: {xml_len}")

        xml_content = content[4:xml_len + 4]
        from_corp_id = content[xml_len + 4:].decode('utf-8').rstrip('\0')
        logger.info(f"解密得到的corp_id: '{from_corp_id}'")
        logger.info(f"预期的corp_id: '{corp_id}'")

        # 验证corp_id
        if from_corp_id != corp_id:
            logger.error(f"Corp ID不匹配!")
            return None

        result = xml_content.decode('utf-8')
        logger.info(f"解密成功: {result}")
        return result

    except Exception as e:
        logger.error(f"解密失败: {e}")
        logger.error(f"错误详情: {traceback.format_exc()}")
        return None


def verify_signature(token, timestamp, nonce, encrypt_msg):
    """验证签名"""
    try:
        logger.info(f"开始验证签名")
        logger.debug(f"Token: {token}")
        logger.debug(f"Timestamp: {timestamp}")
        logger.debug(f"Nonce: {nonce}")
        logger.debug(f"Encrypt_msg: {encrypt_msg[:50]}...")

        # 排序并拼接
        sort_list = [token, timestamp, nonce, encrypt_msg]
        sort_list.sort()
        sha1_str = ''.join(sort_list)
        logger.debug(f"排序后字符串: {sha1_str[:100]}...")

        # SHA1哈希
        sha1 = hashlib.sha1(sha1_str.encode('utf-8')).hexdigest()
        logger.info(f"计算得到的签名: {sha1}")
        return sha1

    except Exception as e:
        logger.error(f"签名验证失败: {e}")
        logger.error(f"错误详情: {traceback.format_exc()}")
        return None


@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    logger.info(f"=== 收到{request.method}请求 ===")
    logger.info(f"请求URL: {request.url}")
    logger.info(f"请求头: {dict(request.headers)}")
    logger.info(f"请求参数: {dict(request.args)}")

    if request.method == 'GET':
        # URL验证
        msg_signature = request.args.get('msg_signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')

        logger.info(f"验证参数:")
        logger.info(f"  msg_signature: {msg_signature}")
        logger.info(f"  timestamp: {timestamp}")
        logger.info(f"  nonce: {nonce}")
        logger.info(f"  echostr: {echostr[:50]}... (长度: {len(echostr)})")

        # 检查必要参数
        if not all([msg_signature, timestamp, nonce, echostr]):
            logger.error("缺少必要参数")
            return "Missing required parameters", 400

        # 计算签名
        calculated_signature = verify_signature(TOKEN, timestamp, nonce, echostr)

        if calculated_signature == msg_signature:
            logger.info("✓ 签名验证成功，开始解密...")

            # 解密echostr
            decrypted = decrypt_msg(echostr, ENCODING_AES_KEY, CORP_ID)
            if decrypted:
                logger.info(f"✓ 解密成功，返回: {decrypted}")
                return decrypted
            else:
                logger.error("✗ 解密失败")
                return "decrypt failed", 400
        else:
            logger.error(f"✗ 签名验证失败!")
            logger.error(f"预期签名: {msg_signature}")
            logger.error(f"计算签名: {calculated_signature}")
            return "signature verification failed", 400

    elif request.method == 'POST':
        logger.info("收到POST消息")
        return "success"

    return "Invalid request method", 405


@app.route('/test', methods=['GET'])
def test():
    """测试接口"""
    logger.info("测试接口被调用")
    return "Webhook服务运行正常"


@app.route('/config', methods=['GET'])
def show_config():
    """显示当前配置（用于调试）"""
    return {
        "token_length": len(TOKEN),
        "encoding_aes_key_length": len(ENCODING_AES_KEY),
        "corp_id": CORP_ID,
        "service_status": "running"
    }


if __name__ == '__main__':
    logger.info("=== 启动Webhook验证服务 ===")
    logger.info(f"TOKEN长度: {len(TOKEN)}")
    logger.info(f"ENCODING_AES_KEY长度: {len(ENCODING_AES_KEY)}")
    logger.info(f"CORP_ID: {CORP_ID}")

    app.run(host='0.0.0.0', port=11850, debug=True)