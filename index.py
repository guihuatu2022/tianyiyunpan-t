import time
import os
import random
import json
import base64
import hashlib
import rsa
import requests
import re
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from urllib.parse import urlparse

# 常量定义
BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
MAX_TOTAL_TIME = 300  # 总签到时间上限（5分钟=300秒）

def mask_phone(phone):
    """隐藏手机号中间四位"""
    return phone[:3] + "****" + phone[-4:] if len(phone) == 11 else phone

def int2char(a):
    """将数字转换为对应的字符"""
    return BI_RM[a]

def b64tohex(a):
    """Base64字符串转换为十六进制字符串"""
    d = ""
    e = 0
    c = 0
    for i in range(len(a)):
        if list(a)[i] != "=":
            v = B64MAP.index(list(a)[i])
            if 0 == e:
                e = 1
                d += int2char(v >> 2)
                c = 3 & v
            elif 1 == e:
                e = 2
                d += int2char(c << 2 | v >> 4)
                c = 15 & v
            elif 2 == e:
                e = 3
                d += int2char(c)
                d += int2char(v >> 2)
                c = 3 & v
            else:
                e = 0
                d += int2char(c << 2 | v >> 4)
                d += int2char(15 & v)
    if e == 1:
        d += int2char(c << 2)
    return d

def rsa_encode(j_rsakey, string):
    """使用RSA公钥加密字符串"""
    rsa_key = f"-----BEGIN PUBLIC KEY-----\n{j_rsakey}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
    result = b64tohex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
    return result

def login(username, password):
    """登录天翼云盘（优化执行速度）"""
    print("🔄 正在执行登录流程...")
    session = requests.Session()
    # 设置超时时间为5秒，加快失败响应
    session.timeout = 5
    try:
        # 获取登录令牌
        url_token = "https://m.cloud.189.cn/udb/udb_login.jsp?pageId=1&pageKey=default&clientType=wap&redirectURL=https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html"
        response = session.get(url_token)
        match = re.search(r"https?://[^\s'\"]+", response.text)
        if not match:
            print("❌ 错误：未找到动态登录页")
            return None
            
        # 获取登录页面
        url = match.group()
        response = session.get(url)
        match = re.search(r"<a id=\"j-tab-login-link\"[^>]*href=\"([^\"]+)\"", response.text)
        if not match:
            print("❌ 错误：登录入口获取失败")
            return None
            
        # 解析登录参数
        href = match.group(1)
        response = session.get(href)
        
        captcha_token = re.findall(r"captchaToken' value='(.+?)'", response.text)[0]
        lt = re.findall(r'lt = "(.+?)"', response.text)[0]
        return_url = re.findall(r"returnUrl= '(.+?)'", response.text)[0]
        param_id = re.findall(r'paramId = "(.+?)"', response.text)[0]
        j_rsakey = re.findall(r'j_rsaKey" value="(\S+)"', response.text, re.M)[0]
        session.headers.update({"lt": lt})

        # RSA加密用户名和密码
        username_encrypted = rsa_encode(j_rsakey, username)
        password_encrypted = rsa_encode(j_rsakey, password)
        
        # 准备登录数据
        data = {
            "appKey": "cloud",
            "accountType": '01',
            "userName": f"{{RSA}}{username_encrypted}",
            "password": f"{{RSA}}{password_encrypted}",
            "validateCode": "",
            "captchaToken": captcha_token,
            "returnUrl": return_url,
            "mailSuffix": "@189.cn",
            "paramId": param_id
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
            "Referer": "https://open.e.189.cn/",
        }
        
        # 提交登录请求
        response = session.post(
            "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do",
            data=data,
            headers=headers
        )
        
        # 检查登录结果
        if response.json().get('result', 1) != 0:
            print(f"❌ 登录错误：{response.json().get('msg')}")
            return None
            
        # 跳转到返回URL完成登录
        session.get(response.json()['toUrl'])
        print("✅ 登录成功")
        return session
        
    except Exception as e:
        print(f"⚠️ 登录异常：{str(e)}")
        return None

def translate_error(code):
    """将错误码翻译为中文提示"""
    error_map = {
        "User_Not_Chance": "今日已无抽奖机会",
        "ERROR_USER_NOT_SIGN_IN": "未签到，无法抽奖",
        "SYSTEM_ERROR": "系统错误，请稍后再试",
        "INVALID_TOKEN": "登录已过期",
        "FREQUENCY_LIMIT": "操作过于频繁，请稍后再试"
    }
    # 查找对应的中文翻译，没有则返回原始错误码
    return error_map.get(code, code)

def send_wxpusher(msg):
    """发送消息到WxPusher"""
    # 从环境变量获取WxPusher配置
    app_token = os.getenv("WXPUSHER_APP_TOKEN")
    uids = os.getenv("WXPUSHER_UID", "").split('&')
    
    if not app_token or not uids:
        print("⚠️ 未配置WxPusher，跳过消息推送")
        return
    
    url = "https://wxpusher.zjiecode.com/api/send/message"
    headers = {"Content-Type": "application/json"}
    
    for uid in uids:
        data = {
            "appToken": app_token,
            "content": msg,
            "contentType": 3,  # HTML格式
            "topicIds": [],
            "uids": [uid],
        }
        try:
            response = requests.post(url, json=data, headers=headers, timeout=10)
            if response.json().get('code') == 1000:
                print(f"✅ 消息推送成功 -> UID: {uid}")
            else:
                print(f"❌ 消息推送失败：{response.text}")
        except Exception as e:
            print(f"❌ 推送异常：{str(e)}")

def send_email(msg):
    """发送邮件通知"""
    # 从环境变量获取邮箱配置
    smtp_server = os.getenv("EMAIL_SMTP_SERVER")  # 例如: smtp.qq.com
    smtp_port = int(os.getenv("EMAIL_SMTP_PORT", 465))  # 通常是465
    sender = os.getenv("EMAIL_SENDER")  # 发件人邮箱
    sender_password = os.getenv("EMAIL_PASSWORD")  # 邮箱密码/授权码
    receiver = os.getenv("EMAIL_RECEIVER")  # 收件人邮箱
    
    # 检查邮箱配置是否完整
    if not all([smtp_server, sender, sender_password, receiver]):
        print("⚠️ 未配置完整的邮箱参数，跳过邮件发送")
        return
    
    try:
        # 创建邮件内容
        message = MIMEText(msg, 'html', 'utf-8')
        message['From'] = sender
        message['To'] = receiver
        message['Subject'] = Header(f'天翼云盘签到结果 {time.strftime("%Y-%m-%d")}', 'utf-8')
        
        # 发送邮件
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            
        server.login(sender, sender_password)
        server.sendmail(sender, receiver.split(','), message.as_string())
        server.quit()
        print(f"✅ 邮件已成功发送至 {receiver}")
        
    except Exception as e:
        print(f"❌ 邮件发送失败：{str(e)}")

def calculate_intervals(total_accounts):
    """根据账号数量计算合理的间隔时间"""
    if total_accounts <= 1:
        return (0, 0)  # 单个账号无需间隔
        
    # 预留60秒作为操作时间，剩余时间用于间隔分配
    available_seconds = MAX_TOTAL_TIME - 60
    if available_seconds < total_accounts:
        available_seconds = total_accounts  # 确保至少每个账号有1秒间隔
        
    # 计算每个账号之间的间隔范围
    min_interval = max(1, int(available_seconds / (total_accounts * 2)))
    max_interval = min(60, int(available_seconds / (total_accounts - 1)))
    
    return (min_interval, max_interval)

def process_account(username, password, interval):
    """处理单个账号的签到和抽奖（带固定间隔）"""
    masked_phone = mask_phone(username)
    account_result = {"username": masked_phone, "sign": "", "lottery": "", "time": ""}
    
    print(f"\n🔔 处理账号：{masked_phone}")
    
    # 如果有间隔时间，先等待
    if interval > 0:
        print(f"⏰ 等待 {interval} 秒后执行签到")
        time.sleep(interval)
    
    # 记录签到时间
    sign_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    account_result["time"] = sign_time
    print(f"📅 开始签到时间：{sign_time}")
    
    # 登录流程
    session = login(username, password)
    if not session:
        account_result["sign"] = "❌ 登录失败"
        return account_result
    
    # 签到流程（简化操作，加快执行）
    try:
        # 每日签到
        rand = str(round(time.time() * 1000))
        sign_url = f'https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
            "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
            "Host": "m.cloud.189.cn",
        }
        response = session.get(sign_url, headers=headers).json()
        
        if 'isSign' in response:
            if response.get('isSign') == "false":
                account_result["sign"] = f"✅ +{response.get('netdiskBonus', '0')}M"
            else:
                account_result["sign"] = f"⏳ 已签到+{response.get('netdiskBonus', '0')}M"
        else:
            account_result["sign"] = f"❌ 签到失败: {response.get('errorMsg', '未知错误')}"
        
        # 单次抽奖（缩短等待时间）
        time.sleep(random.randint(0, 1))  # 0-1秒随机等待
        lottery_url = 'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN'
        response = session.get(lottery_url, headers=headers).json()
        
        if "errorCode" in response:
            # 翻译错误码为中文
            error_msg = translate_error(response.get('errorCode'))
            account_result["lottery"] = f"❌ {error_msg}"
        else:
            prize = response.get('prizeName') or response.get('description', '未知奖品')
            account_result["lottery"] = f"🎁 {prize}"
            
    except Exception as e:
        account_result["sign"] = "❌ 操作异常"
        account_result["lottery"] = f"⚠️ {str(e)}"
    
    print(f"  {account_result['sign']} | {account_result['lottery']}")
    return account_result

# 云函数入口
def main_handler(event, context):
    """腾讯云函数入口函数"""
    start_time = time.time()
    print("\n=============== 天翼云盘签到开始 ===============")
    print(f"⏱️ 触发时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}")
    print(f"🎯 目标：{MAX_TOTAL_TIME}秒内完成所有账号签到")
    
    # 从环境变量获取账号信息
    usernames = os.getenv("ty_username", "").split('&')
    passwords = os.getenv("ty_password", "").split('&')
    
    # 检查环境变量
    if not usernames or not passwords or not usernames[0] or not passwords[0]:
        error_msg = "❌ 请设置环境变量 ty_username 和 ty_password"
        print(error_msg)
        return {"status": "error", "message": error_msg}
    
    # 确保账号密码数量匹配
    total_accounts = len(usernames)
    if total_accounts != len(passwords):
        error_msg = "❌ 账号和密码数量不匹配"
        print(error_msg)
        return {"status": "error", "message": error_msg}
    
    # 计算账号间的间隔时间
    min_interval, max_interval = calculate_intervals(total_accounts)
    print(f"📊 账号数量：{total_accounts}个，间隔范围：{min_interval}-{max_interval}秒")
    
    # 生成每个账号的间隔时间（第一个账号立即执行）
    intervals = [0]  # 第一个账号无需等待
    for i in range(1, total_accounts):
        intervals.append(random.randint(min_interval, max_interval))
    
    # 处理所有账号
    all_results = []
    for i, (username, password, interval) in enumerate(zip(usernames, passwords, intervals)):
        # 检查是否即将超时，提前终止
        elapsed = time.time() - start_time
        if elapsed + interval + 30 > MAX_TOTAL_TIME:  # 预留30秒操作时间
            print(f"⚠️ 剩余时间不足，跳过账号 {mask_phone(username)}")
            all_results.append({
                "username": mask_phone(username),
                "sign": "❌ 超时跳过",
                "lottery": "",
                "time": ""
            })
            continue
            
        result = process_account(username, password, interval)
        all_results.append(result)
        
        # 实时计算剩余时间
        elapsed = time.time() - start_time
        remaining = MAX_TOTAL_TIME - elapsed
        print(f"⏳ 已用时：{int(elapsed)}秒，剩余时间：{int(remaining)}秒")
    
    # 生成汇总表格（使用HTML表格优化显示效果）
    table = f"<h3>天翼云盘签到汇总 {time.strftime('%Y-%m-%d')}</h3>"
    table += "<table border='1' cellpadding='8' style='border-collapse:collapse;'>"
    table += "<tr bgcolor='#f0f0f0'>"
    table += "<th>账号</th><th>签到时间</th><th>签到结果</th><th>每日抽奖</th>"
    table += "</tr>"
    
    for res in all_results:
        table += "<tr>"
        table += f"<td>{res['username']}</td>"
        table += f"<td>{res['time'] or '-'}</td>"
        table += f"<td>{res['sign']}</td>"
        table += f"<td>{res['lottery'] or '-'}</td>"
        table += "</tr>"
    table += "</table>"
    
    # 发送通知（使用HTML格式）
    send_wxpusher(table)
    send_email(table)
    
    # 总耗时统计
    total_elapsed = int(time.time() - start_time)
    print(f"\n✅ 所有账号处理完成！总耗时：{total_elapsed}秒")
    
    return {
        "status": "success",
        "results": all_results,
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "total_elapsed_seconds": total_elapsed
    }

# 本地测试用
if __name__ == "__main__":
    main_handler(None, None)
    
