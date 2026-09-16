import json
import ssl
import subprocess
import urllib.request
import urllib.error
import ipaddress

# -----------------------------
# URL LISTS
# -----------------------------

DIRECT_URLS = [
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/domainset/apple_cdn.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/apple_cdn.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/apple_cn.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/microsoft_cdn.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/domestic.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/direct.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/lan.json",
    "https://raw.githubusercontent.com/jackszb/sukka/main/direct_custom_rules.json",
]

PROXY_URLS = [
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/domainset/cdn.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/cdn.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/apple_intelligence.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/microsoft.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/global.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/ai.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/stream.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/telegram.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/ip/ai.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/ip/stream.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/ip/telegram.json",
]

REJECT_URLS = [
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/domainset/reject.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/domainset/reject_extra.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/domainset/reject_phishing.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/reject.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/reject-drop.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/reject-no-drop.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/non_ip/sogouinput.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/ip/reject.json",
]

IP_URLS = [
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/ip/china_ip.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/ip/china_ip_ipv6.json",
    "https://raw.githubusercontent.com/jackszb/sukka-json/main/ip/lan.json",
]

# 允许输出的字段(源数据里只会出现 ip_cidr,不存在单独的 ip 字段)
ALLOWED_KEYS = {
    "domain",
    "domain_suffix",
    "domain_keyword",
    "ip_cidr",
}

# 网络请求超时时间(秒)
FETCH_TIMEOUT = 15
# sing-box 编译超时时间(秒)
COMPILE_TIMEOUT = 60

# 生成 .list (Clash 规则集文本格式) 时，字段名 -> 规则类型前缀 的映射
# 以及输出顺序（保证同类规则聚在一起，并用空行分隔各类型，风格与示例一致）
LIST_FIELD_ORDER = ["domain", "domain_suffix", "domain_keyword", "ip_cidr"]

LIST_RULE_TYPE = {
    "domain": "DOMAIN",
    "domain_suffix": "DOMAIN-SUFFIX",
    "domain_keyword": "DOMAIN-KEYWORD",
    "ip_cidr": "IP-CIDR",
}

# 源数据中夹带的作者水印/追踪域名特征。
# 例如: "127.skk.moe", "7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe",
#      "this_ruleset_is_made_by_sukkaw.ruleset.skk.moe"
# 这类域名无实际拦截/分流意义，只是用来追踪规则集是否被未授权转发，
# 合并时统一过滤掉，避免占用体积、影响规则准确性。
WATERMARK_PATTERNS = [
    "skk.moe",
]


def is_watermark_value(value):
    """判断一个字符串值是否命中水印域名特征（大小写不敏感，子串匹配）。"""
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return any(pattern in lowered for pattern in WATERMARK_PATTERNS)


# -----------------------------
# Fetch & merge
# -----------------------------

def process_urls(urls, ssl_context):
    master_rules = {}
    dropped_keys = set()
    watermark_count = 0

    for url in urls:
        url = url.strip()
        if not url:
            continue

        try:
            print(f"  Fetching: {url}")

            with urllib.request.urlopen(url, context=ssl_context, timeout=FETCH_TIMEOUT) as response:
                raw = response.read().decode("utf-8")

            data = json.loads(raw)

            if not (isinstance(data, dict) and isinstance(data.get("rules"), list)):
                print(f"  [WARN] {url}: unexpected structure, no 'rules' list found, skipped")
                continue

            for rule in data["rules"]:
                if not isinstance(rule, dict):
                    print(f"  [WARN] {url}: rule entry is not an object, skipped ({rule!r})")
                    continue

                for key, value in rule.items():
                    if key not in ALLOWED_KEYS:
                        dropped_keys.add(key)
                        continue

                    master_rules.setdefault(key, [])

                    if isinstance(value, list):
                        for item in value:
                            if is_watermark_value(item):
                                watermark_count += 1
                                continue
                            master_rules[key].append(item)
                    else:
                        if is_watermark_value(value):
                            watermark_count += 1
                        else:
                            master_rules[key].append(value)

        except urllib.error.URLError as e:
            print(f"  [NETWORK ERROR] {url}: {e}")
        except json.JSONDecodeError as e:
            print(f"  [JSON ERROR] {url}: invalid JSON ({e})")
        except Exception as e:
            print(f"  [ERROR] {url}: {e}")

    if dropped_keys:
        print(f"  [INFO] Ignored unknown/unsupported keys from this batch: {sorted(dropped_keys)}")

    if watermark_count:
        print(f"  [INFO] Filtered out {watermark_count} watermark/tracking domain(s)")

    return master_rules


# -----------------------------
# IP SORT (修复版：去重放在解析之后，用规范化的 IP 对象去重)
# -----------------------------

def sort_ip_list(values):
    # 用 dict 保存"解析后的网段对象 -> None"，dict/set 的 key 会自动按值判断相等，
    # 这样 "1.2.3.4" 和 "1.2.3.4/32"、"2001:DB8::/32" 和 "2001:db8::/32"
    # 这类写法不同但语义相同的地址，会被正确识别为同一个,不会重复出现在结果里。
    ipv4_seen = {}
    ipv6_seen = {}

    invalid_count = 0
    non_str_count = 0

    for v in values:
        if not isinstance(v, str):
            non_str_count += 1
            continue

        v = v.strip()
        if not v:
            continue

        try:
            ip_obj = ipaddress.ip_network(v, strict=False)
        except Exception:
            # 不是合法 IP/CIDR，直接忽略（避免崩）
            invalid_count += 1
            continue

        if isinstance(ip_obj, ipaddress.IPv4Network):
            ipv4_seen[ip_obj] = None
        else:
            ipv6_seen[ip_obj] = None

    if non_str_count:
        print(f"  [WARN] ip_cidr: dropped {non_str_count} non-string value(s)")
    if invalid_count:
        print(f"  [WARN] ip_cidr: dropped {invalid_count} invalid/unparseable value(s)")

    # 合并相邻/重叠/被包含的网段，减少条目数量（与 merge_ip.py 的 collapse() 行为保持一致）
    ipv4_collapsed = list(ipaddress.collapse_addresses(ipv4_seen.keys()))
    ipv6_collapsed = list(ipaddress.collapse_addresses(ipv6_seen.keys()))

    ipv4_sorted = sorted(ipv4_collapsed, key=lambda x: (int(x.network_address), x.prefixlen))
    ipv6_sorted = sorted(ipv6_collapsed, key=lambda x: (int(x.network_address), x.prefixlen))

    return [str(x) for x in ipv4_sorted + ipv6_sorted]


def safe_sorted_unique(values, field_name):
    """对普通字符串字段做去重排序,过滤掉非字符串类型并给出警告,避免 sorted() 因类型混杂而抛错。"""
    str_values = []
    non_str_count = 0

    for v in values:
        if isinstance(v, str):
            str_values.append(v)
        else:
            non_str_count += 1

    if non_str_count:
        print(f"  [WARN] field '{field_name}': dropped {non_str_count} non-string value(s)")

    return sorted(set(str_values))


# -----------------------------
# Generate .list (Clash text rule-set)
# -----------------------------

def generate_list_file(final_rule, list_file):
    """
    根据 final_rule（已去重排序好的字段字典）生成 Clash 风格的文本规则文件，
    格式示例:
        DOMAIN,api.blipsandchitz.me
        DOMAIN,cn.alibabacloud.com

        DOMAIN-SUFFIX,10155.com

        DOMAIN-KEYWORD,liuyimin3

        IP-CIDR,0.0.0.0/8,no-resolve
    每种规则类型之间用空行分隔；ip_cidr 额外追加 ",no-resolve"。
    """
    blocks = []

    for key in LIST_FIELD_ORDER:
        values = final_rule.get(key)
        if not values:
            continue

        rule_type = LIST_RULE_TYPE[key]
        lines = []
        for v in values:
            if key == "ip_cidr":
                lines.append(f"{rule_type},{v},no-resolve")
            else:
                lines.append(f"{rule_type},{v}")

        blocks.append("\n".join(lines))

    content = "\n\n".join(blocks)
    if content:
        content += "\n"

    with open(list_file, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"  LIST saved: {list_file}")


# -----------------------------
# Save JSON + compile SRS
# -----------------------------

def save_json_and_compile(master_rules, json_file, srs_file, allowed_keys=None, list_file=None):
    final_rule = {}

    # 先处理普通 domain 类字段
    # allowed_keys 用于限制本次输出只保留哪些字段(不传则默认所有 domain 类字段)
    domain_like_keys = (allowed_keys if allowed_keys is not None else ALLOWED_KEYS) - {"ip_cidr"}
    for key in domain_like_keys:
        values = master_rules.get(key)
        if not values:
            continue
        final_rule[key] = safe_sorted_unique(values, key)

    # ip_cidr 走专门的 IPv4/IPv6 排序去重逻辑（仅当 ip_cidr 在允许的字段范围内时才输出）
    effective_keys = allowed_keys if allowed_keys is not None else ALLOWED_KEYS
    if "ip_cidr" in effective_keys:
        ip_values = master_rules.get("ip_cidr")
        if ip_values:
            final_rule["ip_cidr"] = sort_ip_list(ip_values)

    data = {
        "version": 5,
        "rules": [final_rule]
    }

    # -----------------------------
    # SAVE JSON
    # -----------------------------
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"  JSON saved: {json_file}")

    # -----------------------------
    # SAVE LIST (Clash text format)
    # -----------------------------
    if list_file:
        generate_list_file(final_rule, list_file)

    # -----------------------------
    # COMPILE SRS
    # -----------------------------
    try:
        result = subprocess.run(
            ["sing-box", "rule-set", "compile", "--output", srs_file, json_file],
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
        )

        if result.returncode == 0:
            print(f"  SRS compiled: {srs_file}")
        else:
            print(f"  [SRS ERROR]: {result.stderr}")

    except FileNotFoundError:
        print("  [WARNING] sing-box not found, only JSON generated")
    except subprocess.TimeoutExpired:
        print(f"  [SRS ERROR]: compile timed out after {COMPILE_TIMEOUT}s")


# -----------------------------
# MAIN
# -----------------------------

def main():
    # 使用默认的证书校验上下文(raw.githubusercontent.com 证书有效,无需关闭校验)
    ssl_context = ssl.create_default_context()

    # direct/proxy/reject
    DOMAIN_ONLY_KEYS = {"domain", "domain_suffix", "domain_keyword", "ip_cidr"}

    print("\n=== DIRECT ===")
    direct = process_urls(DIRECT_URLS, ssl_context)
    save_json_and_compile(
        direct, "direct_rules.json", "direct_rules.srs",
        allowed_keys=DOMAIN_ONLY_KEYS, list_file="direct_rules.list",
    )

    print("\n=== PROXY ===")
    proxy = process_urls(PROXY_URLS, ssl_context)
    save_json_and_compile(
        proxy, "proxy_rules.json", "proxy_rules.srs",
        allowed_keys=DOMAIN_ONLY_KEYS, list_file="proxy_rules.list",
    )

    print("\n=== REJECT ===")
    reject = process_urls(REJECT_URLS, ssl_context)
    save_json_and_compile(
        reject, "reject_rules.json", "reject_rules.srs",
        allowed_keys=DOMAIN_ONLY_KEYS, list_file="reject_rules.list",
    )

    print("\n=== IP ===")
    ip = process_urls(IP_URLS, ssl_context)
    save_json_and_compile(
        ip, "ip_rules.json", "ip_rules.srs",
        allowed_keys={"ip_cidr"}, list_file="ip_rules.list",
    )

    print("\n=== ALL DONE ===")


if __name__ == "__main__":
    main()
