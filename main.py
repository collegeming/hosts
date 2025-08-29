import json
import os
import dns.resolver
import socket
import time
import statistics
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

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

# 测量IP地址延迟（多次测试取平均值）
def measure_latency(ip, port=443, timeout=1.5, retries=5):
    """
    测量给定IP地址的TCP连接延迟（多次测试取平均值）
    :param ip: IP地址 (IPv4或IPv6)
    :param port: 测试端口
    :param timeout: 单次测试超时时间（秒）
    :param retries: 测试次数
    :return: 平均延迟（毫秒）或超时返回9999ms
    """
    latencies = []
    
    for _ in range(retries):
        start_time = time.time()
        try:
            # 根据IP类型创建socket
            if ':' in ip:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # 执行连接测试
            sock.connect((ip, port))
            elapsed = (time.time() - start_time) * 1000  # 转换为毫秒
            sock.close()
            latencies.append(elapsed)
        except:
            latencies.append(9999)  # 表示连接超时/失败
        time.sleep(0.1)  # 短暂间隔避免网络拥塞
    
    # 计算平均延迟（排除超时值）
    valid_latencies = [lat for lat in latencies if lat < 9999]
    
    if valid_latencies:
        avg_latency = statistics.mean(valid_latencies)
        return avg_latency
    else:
        return 9999

# 获取最佳IP地址（同时处理IPv4和IPv6）
def get_best_ips(ipv4_list, ipv6_list):
    """
    从IPv4和IPv6列表中分别找出延迟最低的最佳IP地址
    :param ipv4_list: IPv4地址列表
    :param ipv6_list: IPv6地址列表
    :return: 元组 (最佳IPv4地址, 最佳IPv6地址)
    """
    best_ipv4 = None
    best_ipv6 = None
    
    # 使用线程池并发测试所有IP地址的延迟
    all_ips = []
    if ipv4_list:
        all_ips.extend([(ip, "ipv4") for ip in ipv4_list])
    if ipv6_list:
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
            except Exception as e:
                print(f"测量{ip}延迟时出错: {str(e)}")
                results.append((ip, ip_type, 9999))
    
    # 分别找出IPv4和IPv6中延迟最低的IP
    ipv4_results = [(ip, lat) for ip, ip_type, lat in results if ip_type == "ipv4"]
    ipv6_results = [(ip, lat) for ip, ip_type, lat in results if ip_type == "ipv6"]
    
    if ipv4_results:
        best_ipv4, min_latency_v4 = min(ipv4_results, key=lambda x: x[1])
        # 筛选延迟低于800ms的IP
        valid_ipv4 = [ip for ip, lat in ipv4_results if lat < 800]
        if valid_ipv4:
            best_ipv4 = min(valid_ipv4, key=lambda x: x[1])[0]
        print(f"IPv4最佳IP: {best_ipv4} (延迟: {min_latency_v4:.2f}ms)")
    
    if ipv6_results:
        best_ipv6, min_latency_v6 = min(ipv6_results, key=lambda x: x[1])
        # 筛选延迟低于800ms的IP
        valid_ipv6 = [ip for ip, lat in ipv6_results if lat < 800]
        if valid_ipv6:
            best_ipv6 = min(valid_ipv6, key=lambda x: x[1])[0]
        print(f"IPv6最佳IP: {best_ipv6} (延迟: {min_latency_v6:.2f}ms)")
    
    return (best_ipv4, best_ipv6)

# DNS解析（同时获取A和AAAA记录）
def dns_lookup(domain):
    """
    同时查询域名的IPv4和IPv6地址
    :param domain: 域名
    :return: 字典包含IPv4和IPv6地址列表
    """
    result = {"ipv4": [], "ipv6": []}
    
    try:
        # 查询IPv4地址
        answers = dns.resolver.resolve(domain, "A")
        result["ipv4"] = [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception as e:
        print(f"解析{domain}的IPv4地址时出错: {str(e)}")
    
    try:
        # 查询IPv6地址
        answers = dns.resolver.resolve(domain, "AAAA")
        result["ipv6"] = [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception as e:
        print(f"解析{domain}的IPv6地址时出错: {str(e)}")
    
    return result

# 加载域名数据
def load_domain_data(filename):
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print("文件 domain.json 不存在")
        return {}
    except json.JSONDecodeError:
        print("文件 domain.json 格式错误")
        return {}

# 主程序
def main(filename):
    domain_data = load_domain_data(filename)
    resolved_domains = {}
    update_time = get_bj_time_str()
    
    # 获取所有唯一域名
    all_domains = set(domain for domains in domain_data.values() for domain in domains)
    
    print(f"开始处理 {len(all_domains)} 个域名的DNS解析...")
    
    # 使用线程池执行DNS解析
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {executor.submit(dns_lookup, domain): domain for domain in all_domains}
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                resolved_domains[domain] = future.result()
            except Exception as e:
                print(f"解析{domain}时出错: {str(e)}")
                resolved_domains[domain] = {"ipv4": [], "ipv6": []}
    
    print("DNS解析完成，开始测试IP延迟...")
    
    # 筛选最佳IP
    domain_best_ips = {}
    
    for domain, ips in resolved_domains.items():
        ipv4_list = ips["ipv4"]
        ipv6_list = ips["ipv6"]
        
        # 获取最佳IPv4和IPv6地址
        best_ipv4, best_ipv6 = get_best_ips(ipv4_list, ipv6_list)
        
        best_ips = {}
        if best_ipv4:
            best_ips["ipv4"] = best_ipv4
        if best_ipv6:
            best_ips["ipv6"] = best_ipv6
        
        domain_best_ips[domain] = best_ips
    
    print("IP延迟测试完成，开始生成hosts文件...")
    
    # 生成hosts文件内容
    key_content = {}
    hosts_content = ""
    
    for key, domains in domain_data.items():
        content = f"# {key} Hosts Start\n"
        for domain in domains:
            best_ips = domain_best_ips.get(domain, {})
            
            # 优先写入IPv6地址
            if "ipv6" in best_ips:
                content += f"{best_ips['ipv6']}\t\t{domain}\n"
            
            # 其次写入IPv4地址
            if "ipv4" in best_ips:
                content += f"{best_ips['ipv4']}\t\t{domain}\n"
        
        content += f"# Update Time: {update_time} (UTC+8)\n"
        content += f"# Update URL: https://raw.githubusercontent.com/oopsunix/hosts/main/hosts_{key.lower()}\n"
        content += f"# {key} Hosts End\n\n"
        key_content[key] = content
        hosts_content += content
    
    # 写入各个分组文件
    #for key, contents in key_content.items():
    #    write_to_file(contents, f'hosts_{key.lower()}')
    
    # 写入总hosts文件
    hosts_content += f"# Total Update Time: {update_time} (UTC+8)\n"
    hosts_content += f"# Update URL: https://raw.githubusercontent.com/oopsunix/hosts/main/hosts"
    write_to_file(hosts_content, 'hosts')
    
    print("Hosts文件更新成功")

if __name__ == '__main__':
    execPath = os.getcwd()
    domainFile = os.path.join(execPath, "domain.json")
    main(domainFile)
