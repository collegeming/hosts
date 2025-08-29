import json
import os
import dns.resolver
import socket
import time
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

# 测量IP地址延迟
def measure_latency(ip, port=443, timeout=1.5):
    """
    测量给定IP地址的TCP连接延迟
    :param ip: IP地址 (IPv4或IPv6)
    :param port: 测试端口
    :param timeout: 超时时间（秒）
    :return: 延迟（毫秒）或超时返回9999ms
    """
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
        return elapsed
    except:
        return 9999  # 表示连接超时/失败

# 获取最佳IP地址
def get_best_ip(ips, protocol='ipv4'):
    """
    从IP列表中找出延迟最低的最佳IP地址
    :param ips: IP地址列表
    :param protocol: 协议类型（仅用于日志）
    :return: 最佳IP地址或None
    """
    if not ips:
        return None
        
    # 使用线程池并发测试所有IP地址的延迟
    with ThreadPoolExecutor(max_workers=min(20, len(ips))) as executor:
        future_to_ip = {executor.submit(measure_latency, ip): ip for ip in ips}
        results = []
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                latency = future.result()
                results.append((ip, latency))
            except Exception as e:
                print(f"测量{ip}延迟时出错: {str(e)}")
                results.append((ip, 9999))
    
    # 找出延迟最低的IP
    best_ip, min_latency = min(results, key=lambda x: x[1])
    
    # 筛选延迟低于800ms的IP
    valid_ips = [(ip, lat) for ip, lat in results if lat < 800]
    
    if valid_ips:
        best_valid_ip = min(valid_ips, key=lambda x: x[1])[0]
        print(f"{protocol}最佳IP: {best_valid_ip} (延迟: {min_latency:.2f}ms)")
        return best_valid_ip
    
    return None if min_latency >= 9999 else best_ip

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
        best_ips = {}
        
        # 获取最佳IPv6地址
        if ips["ipv6"]:
            best_ipv6 = get_best_ip(ips["ipv6"], "IPv6")
            if best_ipv6:
                best_ips["ipv6"] = best_ipv6
        
        # 获取最佳IPv4地址
        if ips["ipv4"]:
            best_ipv4 = get_best_ip(ips["ipv4"], "IPv4")
            if best_ipv4:
                best_ips["ipv4"] = best_ipv4
        
        domain_best_ips[domain] = best_ips
    
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
