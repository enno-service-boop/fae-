#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
網站監控系統 v2.0
功能：HTTP狀態檢查、內容關鍵字驗證、SSL憑證到期檢查、自動告警
"""

import json
import os
import time
import smtplib
import requests
import ssl
import socket
import datetime
import urllib3
from urllib.parse import urlparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional

# 停用非安全請求警告，避免輸出雜訊
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========== 配置載入模組 ==========

def load_config():
    config = {'global_settings': {}, 'targets': []}
    config_file_path = 'config.json'

    # 1. 嘗試從檔案載入
    try:
        with open(config_file_path, 'r', encoding='utf-8') as f:
            file_config = json.load(f)
        print(f"✓ 已從 {config_file_path} 載入設定結構。")
        config['targets'] = file_config.get('targets', [])
        config['global_settings'] = file_config.get('global_settings', {})
    except FileNotFoundError:
        # 如果沒有 config.json，嘗試載入範本文件（例如首次在 GitHub Action 中運行）
        try:
            with open('config.example.json', 'r', encoding='utf-8') as f:
                file_config = json.load(f)
            print("ℹ  使用 config.example.json 作為設定結構。")
            config['targets'] = file_config.get('targets', [])
            config['global_settings'] = file_config.get('global_settings', {})
        except FileNotFoundError:
            print("⚠  未找到任何設定檔，將僅依賴環境變數。")
    except json.JSONDecodeError as e:
        print(f"✗ 設定檔解析錯誤: {e}")

    # 2. 關鍵步驟：用環境變數覆蓋敏感設定（優先級最高）
    sensitive_keys = ['smtp_server', 'smtp_port', 'sender_email', 'sender_password']
    env_mapping = {
        'smtp_server': os.getenv('SMTP_SERVER'),
        'smtp_port': os.getenv('SMTP_PORT'),
        'sender_email': os.getenv('SENDER_EMAIL'),
        'sender_password': os.getenv('  '),
    }
    for key in sensitive_keys:
        env_value = env_mapping[key]
        if env_value is not None and env_value != '':
            # 環境變數存在，則覆蓋檔案中的設定
            config['global_settings'][key] = int(env_value) if key == 'smtp_port' else env_value
            print(f"  ↳  [{key}] 已從環境變數載入。")
        elif key not in config['global_settings'] or config['global_settings'].get(key) in (None, "", "your_*"):
            # 環境變數不存在，且檔案中該設定為空或佔位符，則報錯
            if key == 'sender_password':
                raise ValueError(f"缺少必要設定: '{key}'。請設定環境變數或確保其在設定檔中有效。")

    # 3. 設定其他全域設定的預設值
    config['global_settings'].setdefault('monitor_interval_seconds', 300)
    config['global_settings'].setdefault('timeout_seconds', 30)
    config['global_settings'].setdefault('ssl_warning_days', 30)
    config['global_settings'].setdefault('max_response_time_ms', 5000)

    return config


# ========== 核心檢查函式 ==========

def check_website_with_retry(url: str, timeout: int, verify_ssl: bool = True, retries: int = 2) -> Dict[str, Any]:

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    
    # **關鍵設定**：為特定域名建立不驗證 SSL 的會話
    # 這解決了 TWCA 等私有或特定 CA 簽發憑證的驗證問題。
    # 警告：這會使連線暴露於中間人攻擊，僅在信任的網路環境中使用。
    session = requests.Session()
    if hostname == 'ghgwatch.tpark.com.tw':
        session.verify = False
        # print(f"  ℹ  已為 {hostname} 停用 SSL 憑證驗證。")
    elif not verify_ssl:
        session.verify = False
    # 其他情況使用預設驗證 (verify=True)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    last_error = None
    for attempt in range(retries + 1):  # 總嘗試次數 = retries + 1
        try:
            start_time = time.time()
            response = session.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            response_time = round((time.time() - start_time) * 1000, 2)
            
            return {
                'success': True,
                'status_code': response.status_code,
                'response_time': response_time,
                'content_size': len(response.content),
                'final_url': response.url,
                'attempts': attempt + 1
            }
            
        except requests.exceptions.SSLError as e:
            last_error = f"SSL 錯誤（嘗試 {attempt + 1}/{retries + 1}）: {e}"
        except requests.exceptions.Timeout:
            last_error = f"連線逾時（嘗試 {attempt + 1}/{retries + 1}）"
        except requests.exceptions.ConnectionError as e:
            last_error = f"無法連線（嘗試 {attempt + 1}/{retries + 1}）: {e}"
        except Exception as e:
            last_error = f"其他錯誤（嘗試 {attempt + 1}/{retries + 1}）: {str(e)}"
        
        # 如果不是最後一次嘗試，等待後重試
        if attempt < retries:
            time.sleep(1)
    
    # 所有重試均失敗
    return {'success': False, 'message': f'所有 {retries + 1} 次嘗試均失敗。最後錯誤: {last_error}'}

def check_ssl_expiry(url: str, timeout: int) -> Dict[str, Any]:
    """
    檢查 SSL 憑證的到期日。
    使用低階 socket 連接，獨立於 requests 的驗證設定。
    
    Args:
        url: 要檢查的 HTTPS 網址。
        timeout: 連線逾時時間（秒）。
        
    Returns:
        包含憑證資訊的字典。
    """
    try:
        hostname = urlparse(url).hostname
        if not hostname or not url.startswith('https://'):
            return {'success': False, 'message': '非 HTTPS 網址'}
        
        # 建立 SSL 連線上下文
        context = ssl.create_default_context()
        context.check_hostname = True  # 驗證主機名稱
        context.verify_mode = ssl.CERT_REQUIRED  # 要求驗證憑證
        
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                if not cert or 'notAfter' not in cert:
                    return {'success': False, 'message': '無法從連線取得憑證資訊'}
                
                # 解析憑證到期日
                expiry_str = cert['notAfter']
                date_formats = ['%b %d %H:%M:%S %Y %Z', '%Y%m%d%H%M%SZ', '%b %d %H:%M:%S %Y GMT']
                expiry_date = None
                
                for fmt in date_formats:
                    try:
                        expiry_date = datetime.datetime.strptime(expiry_str, fmt)
                        break
                    except ValueError:
                        continue
                
                if not expiry_date:
                    return {'success': False, 'message': f'無法解析憑證日期格式: {expiry_str}'}
                
                days_left = (expiry_date - datetime.datetime.utcnow()).days
                
                # 取得憑證頒發者資訊
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer.get('organizationName', issuer.get('commonName', '未知'))
                
                return {
                    'success': True,
                    'days_left': days_left,
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'issuer': issuer_name,
                    'is_valid': days_left > 0
                }
                
    except socket.timeout:
        return {'success': False, 'message': 'SSL 連線逾時'}
    except ssl.SSLError as e:
        # 如果之前網站連線已停用驗證，但此處驗證失敗，可能表示憑證確實有問題
        return {'success': False, 'message': f'SSL 憑證驗證失敗: {e}'}
    except Exception as e:
        return {'success': False, 'message': f'SSL 檢查過程發生錯誤: {str(e)}'}

def check_keyword_in_content(url: str, keyword: str, timeout: int, verify_ssl: bool = True) -> Dict[str, Any]:
    """
    檢查網頁內容中是否包含指定的關鍵字。
    
    Args:
        url: 要檢查的網址。
        keyword: 要尋找的關鍵字。
        timeout: 請求逾時時間（秒）。
        verify_ssl: 是否驗證 SSL 憑證。
        
    Returns:
        包含檢查結果的字典。
    """
    try:
        # 此處使用與 check_website_with_retry 相同的邏輯處理特定域名的 SSL
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        session = requests.Session()
        if hostname == 'ghgwatch.tpark.com.tw':
            session.verify = False
        elif not verify_ssl:
            session.verify = False
            
        response = session.get(url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
        
        # 嘗試多種編碼以正確解碼中文內容
        encodings = ['utf-8', 'big5', 'gb2312', 'gbk', 'utf-8-sig']
        for encoding in encodings:
            try:
                content = response.content.decode(encoding)
                if keyword in content:
                    return {'success': True, 'found': True}
            except (UnicodeDecodeError, LookupError):
                continue
        
        # 如果所有編碼都失敗，使用 utf-8 並忽略錯誤
        content = response.content.decode('utf-8', errors='ignore')
        return {'success': True, 'found': keyword in content}
        
    except Exception as e:
        return {'success': False, 'message': f'關鍵字檢查失敗: {str(e)}'}

# ========== 監控與告警邏輯 ==========

def send_alert_email(subject: str, body: str, recipients: List[str], smtp_config: Dict[str, Any]) -> bool:
    """
    發送告警電子郵件。
    
    Args:
        subject: 郵件主旨。
        body: 郵件正文。
        recipients: 收件人郵件列表。
        smtp_config: 包含 SMTP 設定的字典。
        
    Returns:
        發送成功返回 True，否則返回 False。
    """
    if not recipients:
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_config['sender_email']
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = f"[網站監控告警] {subject}"
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        with smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port']) as server:
            server.starttls()
            server.login(smtp_config['sender_email'], smtp_config['sender_password'])
            server.send_message(msg)
        
        print(f"  ✓ 告警郵件已發送給: {recipients}")
        return True
    except Exception as e:
        print(f"  ✗ 發送告警郵件失敗: {e}")
        return False

def monitor_single_site(site_config: Dict[str, Any], global_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    執行對單一網站的完整監控檢查。
    
    Args:
        site_config: 單一站點的設定。
        global_config: 全域設定。
        
    Returns:
        包含所有檢查結果的字典。
    """
    url = site_config['url']
    name = site_config['name']
    
    print(f"\n🔍 檢查: {name} ({url})")
    
    # 初始化結果結構
    results = {
        'name': name,
        'url': url,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'errors': [],
        'warnings': [],
        'status': '✅ 正常'  # 預設狀態
    }
    
    # 1. 檢查網站基本連線狀態
    verify_ssl = site_config.get('verify_ssl', True)
    retries = site_config.get('retries', 2)
    
    website_result = check_website_with_retry(
        url=url,
        timeout=global_config['timeout_seconds'],
        verify_ssl=verify_ssl,
        retries=retries
    )
    
    if not website_result['success']:
        results['errors'].append(website_result['message'])
        results['status'] = '❌ 錯誤'
    else:
        # 記錄成功連線的指標
        results['response_time'] = website_result['response_time']
        results['status_code'] = website_result['status_code']
        results['attempts'] = website_result.get('attempts', 1)
        
        # 檢查 HTTP 狀態碼是否符合預期
        expected_status = site_config.get('expected_status', 200)
        if website_result['status_code'] != expected_status:
            results['errors'].append(
                f"HTTP 狀態碼異常: {website_result['status_code']} (預期: {expected_status})"
            )
            results['status'] = '❌ 錯誤'
        
        # 檢查回應時間是否過長
        max_response_time = site_config.get(
            'max_response_time_ms', 
            global_config.get('max_response_time_ms', 5000)
        )
        if website_result['response_time'] > max_response_time:
            warning_msg = f"回應時間過長: {website_result['response_time']}ms (閾值: {max_response_time}ms)"
            results['warnings'].append(warning_msg)
            if results['status'] == '✅ 正常':
                results['status'] = '⚠️ 警告'
        
        # 2. 檢查網頁內容關鍵字 (僅在連線成功時執行)
        expected_keyword = site_config.get('expected_text')
        if expected_keyword:
            keyword_result = check_keyword_in_content(
                url=url,
                keyword=expected_keyword,
                timeout=global_config['timeout_seconds'],
                verify_ssl=verify_ssl
            )
            
            if not keyword_result['success']:
                results['warnings'].append(f"內容檢查失敗: {keyword_result['message']}")
            elif not keyword_result.get('found', False):
                results['errors'].append(f"頁面內容異常: 找不到關鍵字 '{expected_keyword}'")
                results['status'] = '❌ 錯誤'
    
    # 3. 檢查 SSL 憑證到期日 (僅針對 HTTPS 網站且啟用檢查時)
    if url.startswith('https://') and site_config.get('check_ssl', False):
        ssl_result = check_ssl_expiry(url, global_config['timeout_seconds'])
        
        if ssl_result['success']:
            results['ssl_days_left'] = ssl_result['days_left']
            results['ssl_expiry_date'] = ssl_result['expiry_date']
            
            # 檢查憑證是否即將到期或已過期
            warning_days = global_config.get('ssl_warning_days', 30)
            if ssl_result['days_left'] <= 0:
                results['errors'].append(f"SSL 憑證已過期！")
                results['status'] = '❌ 錯誤'
            elif ssl_result['days_left'] < warning_days:
                warning_msg = f"SSL 憑證即將到期: 剩餘 {ssl_result['days_left']} 天"
                results['warnings'].append(warning_msg)
                if results['status'] == '✅ 正常':
                    results['status'] = '⚠️ 警告'
        else:
            # SSL 檢查失敗，但不一定代表網站無法訪問，記為警告
            results['warnings'].append(f"SSL 憑證檢查失敗: {ssl_result['message']}")
    
    return results

def generate_monitoring_report(results: Dict[str, Any]) -> str:
    """
    為單一網站的檢查結果產生易讀的報告。
    
    Args:
        results: 由 monitor_single_site 產生的結果字典。
        
    Returns:
        格式化的報告字串。
    """
    report_lines = []
    report_lines.append(f"\n📊 {results['name']} 檢查報告")
    report_lines.append("=" * 50)
    report_lines.append(f"狀態: {results['status']}")
    report_lines.append(f"網址: {results['url']}")
    report_lines.append(f"檢查時間: {results['timestamp']}")
    
    # 詳細指標
    if 'response_time' in results:
        attempts_info = f" (嘗試 {results.get('attempts', 1)} 次)" if results.get('attempts', 1) > 1 else ""
        report_lines.append(f"回應時間: {results['response_time']}ms{attempts_info}")
    if 'status_code' in results:
        report_lines.append(f"HTTP 狀態碼: {results['status_code']}")
    if 'ssl_days_left' in results:
        report_lines.append(f"SSL 憑證: 剩餘 {results['ssl_days_left']} 天 (到期: {results['ssl_expiry_date']})")
    
    # 錯誤與警告
    if results['errors']:
        report_lines.append("\n❌ 錯誤:")
        for error in results['errors']:
            report_lines.append(f"  • {error}")
    
    if results['warnings']:
        report_lines.append("\n⚠️  警告:")
        for warning in results['warnings']:
            report_lines.append(f"  • {warning}")
    
    report_lines.append("=" * 50)
    return "\n".join(report_lines)

# ========== 主程式入口 ==========

def main():
    """主程式執行邏輯"""
    print("=" * 60)
    print("🌐 網站監控系統 v2.0")
    print("=" * 60)
    print("功能：連線狀態 | 內容驗證 | SSL憑證 | 自動告警")
    print("=" * 60)
    
    # ===== 核心修改開始：環境檢測 =====
    # 檢測是否在 GitHub Actions 環境中運行
    # GitHub Actions 會自動設定 'GITHUB_ACTIONS' 環境變數為 'true'
    is_github_actions = os.getenv('GITHUB_ACTIONS') == 'true'
    
    if is_github_actions:
        print("⚙️  偵測到 GitHub Actions 環境，執行模式：單次檢查")
        print("   • 腳本將執行一輪完整檢查後自動結束。")
        print("   • 下次檢查將由 GitHub 的排程觸發新任務。")
    else:
        print("⚙️  本地環境，執行模式：持續監控循環")
    print("=" * 60)
    # ===== 核心修改結束 =====
    
    try:
        # 載入配置
        config = load_config()
        global_settings = config['global_settings']
        targets = config['targets']
        
        print(f"📋 載入 {len(targets)} 個監控目標")
        
        # ===== 核心修改：解釋監控間隔 =====
        # 在 GitHub Actions 中，我們會忽略配置檔中的間隔，因為只跑一次。
        # 但日誌仍顯示原始配置值以供參考。
        original_interval = global_settings['monitor_interval_seconds']
        if is_github_actions:
            print(f"⏱  配置監控間隔: {original_interval} 秒 (在 GitHub Actions 中將被忽略，僅執行一次)")
        else:
            print(f"⏱  監控間隔: {original_interval} 秒")
        # ===== 核心修改結束 =====
        
        print(f"🔧 SMTP 伺服器: {global_settings['smtp_server']}:{global_settings['smtp_port']}")
        print("=" * 60)
        
        check_count = 0
        alert_cooldown = {}  # 告警冷卻機制，避免短時間內重複發信
        
        # 主監控迴圈
        while True:
            check_count += 1
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n🔄 第 {check_count} 輪檢查開始 ({current_time})")
            print("-" * 60)
            
            for target in targets:
                # 執行單一網站監控
                site_results = monitor_single_site(target, global_settings)
                
                # 輸出報告
                print(generate_monitoring_report(site_results))
                
                # 檢查是否需要發送告警 (僅在有錯誤且配置了收件人時)
                alert_recipients = target.get('alert_emails', [])
                if site_results['errors'] and alert_recipients:
                    # 簡單的冷卻機制：同一網站每 10 分鐘最多告警一次
                    site_name = site_results['name']
                    last_alert_time = alert_cooldown.get(site_name)
                    
                    if last_alert_time:
                        time_since_last_alert = (datetime.datetime.now() - last_alert_time).total_seconds()
                        if time_since_last_alert < 600:  # 10 分鐘
                            print(f"  ⏳ {site_name} 的告警仍在冷卻中，跳過發信。")
                            continue
                    
                    # 準備告警郵件內容
                    alert_subject = f"{site_results['name']} 發生監控異常"
                    alert_body = f"""
網站監控告警

❌ 異常網站: {site_results['name']}
🔗 網址: {site_results['url']}
⏰ 偵測時間: {site_results['timestamp']}
📊 狀態: {site_results['status']}

錯誤詳情:
{chr(10).join(f'• {error}' for error in site_results['errors'])}

警告訊息:
{chr(10).join(f'• {warning}' for warning in site_results['warnings'])}

技術詳情:
• 回應時間: {site_results.get('response_time', 'N/A')}ms
• HTTP 狀態碼: {site_results.get('status_code', 'N/A')}
• SSL 憑證狀態: {f"剩餘 {site_results.get('ssl_days_left', 'N/A')} 天" if 'ssl_days_left' in site_results else '未檢查/無資料'}

請立即檢查相關服務！
"""
                    
                    # 發送告警郵件
                    if send_alert_email(alert_subject, alert_body, alert_recipients, global_settings):
                        alert_cooldown[site_name] = datetime.datetime.now()
            
            # ===== 核心修改：決定是否繼續循環 =====
            # 如果在 GitHub Actions 環境，執行一輪後立即退出循環
            if is_github_actions:
                print(f"\n✅ GitHub Actions 單次檢查任務完成。程式即將退出。")
                print("=" * 60)
                break  # 跳出 while 循環，程式結束
            
            # 否則（本地環境）：等待設定的間隔後繼續下一輪
            interval = global_settings['monitor_interval_seconds']
            print(f"\n⏳ 本輪檢查完成。等待 {interval} 秒後繼續...")
            print("-" * 60)
            time.sleep(interval)
            # ===== 核心修改結束 =====
            
    except KeyboardInterrupt:
        print("\n\n🛑 監控程式被手動停止。")
    except ValueError as e:
        print(f"\n❌ 設定錯誤: {e}")
        print("請確保已正確設定環境變數或 config.json 檔案。")
        print("必要環境變數: SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD")
    except Exception as e:
        print(f"\n💥 程式執行時發生未預期錯誤: {e}")
        import traceback
        traceback.print_exc()

# ========== 程式進入點 ==========

if __name__ == "__main__":
    main()