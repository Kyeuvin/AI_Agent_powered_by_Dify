from flask import Flask, request
import hashlib
import base64
from Crypto.Cipher import AES
import struct

app = Flask(__name__)

# 企业微信配置（请替换为您的实际配置）
TOKEN = "gbiOBjx9IeIKo"  # 您在企业微信应用中设置的Token
ENCODING_AES_KEY = "5V8ppBRuFTfT7kTlPgYiqXrISLkxYeBWjFbhCzL2NIC"  # 您在企业微信应用中设置的EncodingAESKey
CORP_ID = "ww5a90dfd630815d26"  # 您的企业ID


def decrypt_msg(encrypt_msg, encoding_aes_key, corp_id):
    """解密企业微信消息"""
    try:
        # Base64解码
        key = base64.b64decode(encoding_aes_key + "=")
        encrypt_msg = base64.b64decode(encrypt_msg)

        # AES解密
        iv = key[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypt_msg)

        # 提取消息内容
        content = decrypted[16:]
        xml_len = struct.unpack("I", content[:4])[0]
        xml_content = content[4:xml_len + 4]
        from_corp_id = content[xml_len + 4:].decode('utf-8').rstrip('\0')

        # 验证corp_id
        if from_corp_id != corp_id:
            print(f"Corp ID不匹配: {from_corp_id} != {corp_id}")
            return None

        return xml_content.decode('utf-8')
    except Exception as e:
        print(f"解密失败: {e}")
        return None


def verify_signature(token, timestamp, nonce, encrypt_msg):
    """验证签名"""
    try:
        # 排序并拼接
        sort_list = [token, timestamp, nonce, encrypt_msg]
        sort_list.sort()
        sha1_str = ''.join(sort_list)

        # SHA1哈希
        sha1 = hashlib.sha1(sha1_str.encode('utf-8')).hexdigest()
        return sha1
    except Exception as e:
        print(f"签名验证失败: {e}")
        return None


@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    print(f"收到请求: {request.method}")
    print(f"请求参数: {request.args}")

    if request.method == 'GET':
        # URL验证
        msg_signature = request.args.get('msg_signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')

        print(f"验证参数: signature={msg_signature}, timestamp={timestamp}, nonce={nonce}")

        # 计算签名
        calculated_signature = verify_signature(TOKEN, timestamp, nonce, echostr)
        print(f"计算的签名: {calculated_signature}")

        if calculated_signature == msg_signature:
            print("签名验证成功，开始解密...")
            # 解密echostr
            decrypted = decrypt_msg(echostr, ENCODING_AES_KEY, CORP_ID)
            if decrypted:
                print(f"解密成功: {decrypted}")
                return decrypted
            else:
                print("解密失败")
                return "decrypt failed", 400
        else:
            print("签名验证失败")
            return "signature verification failed", 400

    return "success"


@app.route('/test', methods=['GET'])
def test():
    """测试接口"""
    return "Webhook服务运行正常"


if __name__ == '__main__':
    print("启动Webhook验证服务...")
    print(f"TOKEN: {TOKEN}")
    print(f"CORP_ID: {CORP_ID}")
    app.run(host='0.0.0.0', port=11850, debug=True)