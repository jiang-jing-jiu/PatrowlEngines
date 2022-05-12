# -*- coding: utf-8 -*-
"""
Nessus Engine API Tests
"""

import requests
import json
import time

# 查看引擎状态
def get_engine_status():
    url = "http://192.168.112.160:5001/engines/nessus/status"
    res = requests.get(url=url)
    return res.text

# 发起扫描
def startscan():

    url = "http://192.168.112.160:5002/engines/nessus/startscan"
    data = {
        "scan_id": int(time.time()),
        "assets": [{"id": "1","value": "192.168.112.161","criticity": "low","datatype": "ip"}],
        "options":{
            "name":  "sctirt test 1",
            "action": "scan",
            "policy": "DEFAULT.nessus"
        }
    }
    res = requests.post(url=url,data=json.dumps(data))
    return res.text

# 查看扫描任务状态  1642518651
def get_scan_status():
    url = "http://192.168.112.160:5001/engines/nessus/status/1642518651"
    res = requests.get(url=url)
    return res.text


# 获取扫描任务结果
def getfindings():
    url = "http://192.168.112.160:5001/engines/nessus/getfindings/101"
    res = requests.get(url=url)
    return res.text


# 取消扫描任务
def cleanscan():
    url = "http://192.168.112.160:5001/engines/nessus/clean/1000"
    res = requests.get(url=url)
    return res.text


## 删除Nessus任务————nessus engine未提供二次封装的delete API，但是nessus6rest.py中提供了scan_delete方法，删除基于此方法进行
# def deletescan():
#     url = "http://192.168.112.160:5002/engines/nessus/delete/46"
#     res = requests.get(url=url)
#     return res.text


if __name__ == "__main__":
    # print(get_engine_status())
    # for i in range(50000):    
    #     print(get_engine_status())
    # print(get_scan_status())
    print(getfindings())
    # print(cleanscan())
    #print(deletescan())
    pass