import json
import os
import dns.resolver
import socket
import time
import statistics
import requests
import random
import sys
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置参数
COUNTRY_CODE = 'jp'  # 目标国家代码
TEST_RETRIES = 3     # 每个IP测试次数
TIMEOUT = 1.5        # 连接超时时间（秒）
IPV4_PORT = 80       # IPv4测试端口
IPV6_PORT = 443      # IPv6测试端口

# 检测 IPv6 支持
def is_ipv6_supported():
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.close()
        return True
    except:
        return False

# 获取北京时间
def get_bj_time_str():
    utc_dt = datetime.now(timezone.utc)
    bj_dt = utc_dt.astimezone(timezone(timedelta(hours=8)))
    return bj_dt.strftime("%Y-%m-%d %H:%M:%S")

# 写入文件
def write_to_file(contents, filename):
    with open(filename, 'w') as file:
        file.write(contents)
    print(f"{filename}文件写入成功")

# 从dnschecker.org获取CSRF Token
def get_csrf_token():
    try:
        udp = random.random() * 1000
        url = f'https://dnschecker.org/ajax_files/gen_csrf.php?udp={udp}'
        headers = {
            'referer': f'https://dnschecker.org/country/{COUNTRY_CODE}/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get('csrf')
        return None
    except Exception:
        return None

# 从dnschecker.org获取域名IP地址
def get_dnschecker_ips(domain, record_type, csrf_token):
    try:
        udp = random.random() * 1000
        url = f'https://dnschecker.org/ajax_files/api/220/{record_type}/{domain}?dns_key=country&dns_value={COUNTRY_CODE}&v=0.36&cd_flag=1&upd={udp}'
        headers = {
            'csrftoken': csrf_token,
            'referer': f'https://dnschecker.org/country/{COUNTRY_CODE}/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if 'result' in data and 'ips' in data['result']:
                ips_str = data['result']['ips']
                if '<br />' in ips_str:
                    return [ip.strip() for ip in ips_str.split('<br />') if ip.strip()]
                else:
                    return [ips_str.strip()] if ips_str.strip() else []
    except Exception:
        pass
    return []

# 从dns.resolver获取域名IP地址
def get_resolver_ips(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except:
        return []

# 获取域名所有IP地址（两种来源）
def get_all_ips(domain):
    csrf_token = get_csrf_token()
    ipv4_ips = []
    ipv6_ips = []
    
    # 从dns.resolver获取IP
    resolver_ipv4 = get_resolver_ips(domain, "A")
    resolver_ipv6 = get_resolver_ips(domain, "AAAA") if is_ipv6_supported() else []
    
    # 从dnschecker.org获取IP
    if csrf_token:
        dnschecker_ipv4 = get_dnschecker_ips(domain, "A", csrf_token)
        dnschecker_ipv6 = get_dnschecker_ips(domain, "AAAA", csrf_token) if is_ipv6_supported() else []
    else:
        dnschecker_ipv4 = []
        dnschecker_ipv6 = []
    
    # 合并并去重
    ipv4_ips = list(set(resolver_ipv4 + dnschecker_ipv4))
    ipv6_ips = list(set(resolver_ipv6 + dnschecker_ipv6))
    
    return {"ipv4": ipv4_ips, "ipv6": ipv6_ips}

# 测量IP地址延迟（多次测试取平均值）
def measure_latency(ip):
    latencies = []
    port = IPV6_PORT if ':' in ip else IPV4_PORT
    
    for _ in range(TEST_RETRIES):
        start_time = time.time()
        try:
            # 根据IP类型创建socket
            if ':' in ip:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            
            # 执行连接测试
            sock.connect((ip, port))
            elapsed = (time.time() - start_time) * 1000  # 转换为毫秒
            sock.close()
            latencies.append(elapsed)
        except:
            latencies.append(9999)
        
        time.sleep(0.05)  # 短暂间隔避免网络拥塞
    
    # 计算平均延迟（排除超时值）
    valid_latencies = [lat for lat in latencies if lat < 9999]
    return statistics.mean(valid_latencies) if valid_latencies else 9999

# 获取最佳IP地址
def get_best_ips(ipv4_list, ipv6_list):
    best_ipv4 = None
    best_ipv6 = None
    min_latency_v4 = 9999
    min_latency_v6 = 9999
    
    # 测试所有IP地址的延迟
    all_ips = []
    if ipv4_list:
        all_ips.extend([(ip, "ipv4") for ip in ipv4_list])
    if ipv6_list and is_ipv6_supported():
        all_ips.extend([(ip, "ipv6") for ip in ipv6_list])
    
    if not all_ips:
        return (None, None)
    
    # 创建线程池测试所有IP
    with ThreadPoolExecutor(max_workers=min(20, len(all_ips))) as executor:
        future_to_ip = {executor.submit(measure_latency, ip): (ip, ip_type) for ip, ip_type in all_ips}
        results = []
        
        for future in as_completed(future_to_ip):
            ip, ip_type = future_to_ip[future]
            try:
                latency = future.result()
                results.append((ip, ip_type, latency))
            except:
                results.append((ip, ip_type, 9999))
    
    # 分别找出IPv4和IPv6中延迟最低的IP
    for ip, ip_type, latency in results:
        if ip_type == "ipv4" and latency < min_latency_v4:
            min_latency_v4 = latency
            best_ipv4 = ip
        elif ip_type == "ipv6" and latency < min_latency_v6:
            min_latency_v6 = latency
            best_ipv6 = ip
    
    if best_ipv4:
        print(f"IPv4最佳IP: {best_ipv4} (平均延迟: {min_latency_v4:.2f}ms)")
    if best_ipv6:
        print(f"IPv6最佳IP: {best_ipv6} (平均延迟: {min_latency_v6:.2f}ms)")
    
    return (best_ipv4, best_ipv6)

# 加载域名数据
def load_domain_data(filename):
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except:
        print("无法加载domain.json文件")
        return {}

# 生成Hosts文件内容模板
def generate_hosts_template(group_name, content, update_time):
    return f"""# {group_name} Hosts Start
{content}
# Update Time: {update_time} (UTC+8)
# Update URL: https://raw.githubusercontent.com/collegeming/host/main/hosts_{group_name.lower()}
# Star me: https://github.com/collegeming/host
# {group_name} Hosts End\n\n"""

# 主程序
def main(filename):
    # 检测 IPv6 支持
    ipv6_supported = is_ipv6_supported()
    print(f"系统IPv6支持状态: {'是' if ipv6_supported else '否'}")
    
    domain_data = load_domain_data(filename)
    if not domain_data:
        print("没有找到有效的域名数据")
        return
    
    resolved_domains = {}
    update_time = get_bj_time_str()
    
    # 获取所有唯一域名
    all_domains = set(domain for domains in domain_data.values() for domain in domains)
    print(f"开始处理 {len(all_domains)} 个域名的DNS解析...")
    
    # 使用线程池执行DNS解析
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_domain = {executor.submit(get_all_ips, domain): domain for domain in all_domains}
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                resolved_domains[domain] = future.result()
                ips = resolved_domains[domain]
                print(f"{domain} DNS: IPv4={ips['ipv4']}, IPv6={ips['ipv6']}")
            except Exception as e:
                print(f"解析{domain}时出错: {str(e)}")
                resolved_domains[domain] = {"ipv4": [], "ipv6": []}
    
    print("DNS解析完成，开始测试IP延迟...")
    
    # 筛选最佳IP
    domain_best_ips = {}
    
    for domain, ips in resolved_domains.items():
        ipv4_list = ips["ipv4"]
        ipv6_list = ips["ipv6"] if ipv6_supported else []
        
        # 获取最佳IPv4和IPv6地址
        best_ipv4, best_ipv6 = get_best_ips(ipv4_list, ipv6_list)
        
        best_ips = {}
        if best_ipv4:
            best_ips["ipv4"] = best_ipv4
        if best_ipv6:
            best_ips["ipv6"] = best_ipv6
        
        domain_best_ips[domain] = best_ips
        print(f"{domain} 最佳IP: IPv4={best_ips.get('ipv4', '无')}, IPv6={best_ips.get('ipv6', '无')}")
    
    print("IP延迟测试完成，开始生成hosts文件...")
    
    # 生成hosts文件内容
    key_content = {}
    hosts_content = ""
    
    for group_name, domains in domain_data.items():
        group_content = ""
        for domain in domains:
            best_ips = domain_best_ips.get(domain, {})
            
            # 优先写入IPv6地址
            if "ipv6" in best_ips:
                group_content += f"{best_ips['ipv6']}\t\t{domain}\n"
            
            # 其次写入IPv4地址
            if "ipv4" in best_ips:
                group_content += f"{best_ips['ipv4']}\t\t{domain}\n"
            elif "ipv6" not in best_ips:
                # 如果没有任何IP地址，添加注释
                group_content += f"# 未找到 {domain} 的有效IP地址\n"
        
        # 生成分组Hosts内容
        key_content[group_name] = generate_hosts_template(group_name, group_content, update_time)
        hosts_content += key_content[group_name]
    
    # 写入各个分组文件
    # for key, content in key_content.items():
     #    write_to_file(content, f'hosts_{key.lower()}')
    
    # 写入总hosts文件
    hosts_content += f"# Total Update Time: {update_time} (UTC+8)\n"
    hosts_content += f"# Update URL: https://raw.githubusercontent.com/collegeming/host/main/hosts"
    write_to_file(hosts_content, 'hosts')
    
    print("Hosts文件更新成功")

if __name__ == '__main__':
    execPath = os.getcwd()
    domainFile = os.path.join(execPath, "domain.json")
    
    # 检查是否传递了自定义国家代码参数
    if len(sys.argv) > 1 and len(sys.argv[1]) == 2:
        COUNTRY_CODE = sys.argv[1].lower()
        print(f"使用自定义国家代码: {COUNTRY_CODE}")
    
    main(domainFile)
