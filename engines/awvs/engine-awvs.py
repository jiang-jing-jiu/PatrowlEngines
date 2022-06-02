#!/usr/bin/python3
# -*- coding: utf-8 -*-

# awvs api调用生成target，即便是相同的url，也会生成不同的target_id，
# 因此target_id与实际scan_id应是一一对应的，通过target_id操作scan没问题

import os
import sys
import json
import datetime
import optparse
import requests
from flask import Flask, request, jsonify, redirect, url_for, send_file, send_from_directory
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging


app = Flask(__name__)
APP_DEBUG = os.environ.get('APP_DEBUG', '').lower() in ['true', '1', 'on', 'yes', 'y']
APP_HOST = "0.0.0.0"
APP_PORT = 5445
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 11))

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.awvs = None
this.scanner = {}   # Scanner info
this.scans = {}     # Active scan list

SUCCESS_RES = [200, 201, 204]
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

level_to_value = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
value_to_level = {v: k for k, v in level_to_value.items()}

# Route actions
@app.route('/')
def default():
    return redirect(url_for('index'))


@app.route('/engines/awvs/')
def index():
    return jsonify({"page": "index"})


@app.route('/engines/awvs/reloadconfig')
def reloadconfig():
    res = {"page": "reloadconfig"}
    loadconfig()
    res.update({"config": this.scanner})
    return jsonify(res)

def loadconfig():
    conf_file = BASE_DIR+'/awvs.json'
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
    else:
        this.scanner['status'] = "ERROR"
        return {"status": "ERROR", "reason": "config file not found."}
    
    try:
        # check connection
        api_url = f"{this.scanner['api_url_']}/me"
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }

        r = requests.get(url=api_url, headers=headers, verify=False).json()
        if r['enabled'] == True:
            this.scanner['status'] = "READY"
        else:
            this.scanner['status'] = "Config ERROR"
    except Exception:
        this.scanner['status'] = "Connection ERROR"


# 一个awvs扫描任务里面只可以扫描1个url，这是AWVS扫描器本身设定决定的
@app.route('/engines/awvs/startscan', methods=['POST'])
def start():
    res = {"page": "startscan"}

    # check the scanner is ready to start a new scan
    if len(this.scans) == APP_MAXSCANS:
        res.update({
            "status": "ERROR",
            "reason": "Scan refused: max concurrent active scans reached ({})".format(APP_MAXSCANS)
        })
        return jsonify(res)
    
    scan = {}
    data = json.loads(request.data.decode("utf-8"))

    if 'assets' not in data.keys() or 'scan_id' not in data.keys():  # or not 'base_url' in data['options'].keys():
        res.update({
            "status": "ERROR",
            "reason": "arg error, something is missing (ex: 'assets', 'scan_id')"  #, 'options/base_url')"
        })
        return jsonify(res)
    
    scan["scan_id"] = str(data['scan_id'])
    scan_id = str(data['scan_id'])

    if data["scan_id"] in this.scans.keys():
        res.update({"status": "ERROR", "reason": "scan already started (scan_id={})".format(data["scan_id"])})
        return jsonify(res)

    # Initialize the scan parameters
    asset = data['assets'][0]
    if asset["datatype"] not in this.scanner["allowed_asset_types"]:
        return jsonify({
            "status": "refused",
            "details": {
                "reason": "datatype '{}' not supported for the asset {}.".format(asset["datatype"], asset["value"])
            }})
    
    scan["address"] = list(data['assets'])[0]['value']
    
    # Start the scan
    r = None
    try:
        result_add_target = _add_target(scan["address"])
        if result_add_target is None:
            raise NameError
        scan["target_id"] = result_add_target["target_id"]
        r = _start_scan(scan["target_id"])
        # print(r.status_code)
        if r.status_code in SUCCESS_RES:
            res.update({"status": "accepted"})
            scan["status"] = "SCANNING"
            res.update({"details": r.text})
        else:
            res.update({"status": "ERROR", "reason": "something wrong with the API invokation"})
            scan["status"] = "ERROR"
            scan["finished_at"] = datetime.datetime.now()
    except Exception as error:
        print(error)
        res.update({"status": "ERROR", "reason": "connexion error"})
        scan["status"] = "ERROR"
        scan["finished_at"] = datetime.datetime.now()
    
    # Prepare data returned
    this.scans.update({scan["scan_id"]: scan})
    res.update({"scan": scan})

    return jsonify(res)


# 重置整个awvs，删除所有目标和任务
@app.route('/engines/awvs/clean', methods=['GET'])
def clean():
    res = {"page": "clean"}
    this.scans.clear()
    # 先删除所有的scans，因为scans需要通过targets获取，之后再删除all targets
    _delete_all_scans()
    _delete_all_tatgets()
    loadconfig()
    res.update({"status": "SUCCESS"})
    return jsonify(res)


# clean_scan仅删除this.scans中的scan条目————awvs设置了任务保存时间（目前设置为7天）
@app.route('/engines/awvs/clean/<scan_id>', methods=['GET'])
def clean_scan(scan_id):
    res = {"page": "clean_scan"}
    res.update({"scan_id": scan_id})

    if scan_id not in this.scans.keys():
        res.update({"status": "error",
        "reason": f"scan_id {scan_id} not found"})
        return jsonify(res)
    
    # 由于引擎端接收的scan_id与后端awvs实际的scan的scan_id不是一个值，所以无法通过上面的scan_id删除awvs中的任务
    # 因此通过后端返回的target_id，确定其对应的实际scan_id，以进行删除
    # if _delete_scan_by_target(this.scans[scan_id] ['target_id']) is False:
    #     res.update({"status": "error",
    #     "reason": f"scan_id {scan_id} delete failed"})
    #     return jsonify(res)

    # 删除target
    # if _delete_taget(this.scans[scan_id] ['target_id']) is False:
    #     res.update({"status": "error",
    #     "reason": "target_id delete failed"})
    #     return jsonify(res)

    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)


# Stop all scans
@app.route('/engines/awvs/stopscans', methods=['GET'])
def stop():
    res = {"page": "stopscans"}
    _stop_all_scans()
    res.update({"status": "SUCCESS"})
    return jsonify(res)


@app.route('/engines/awvs/stop/<scan_id>')
def stop_scan(scan_id):
    res = {"page": "stop"}

    if scan_id not in this.scans.keys():
        res.update({"status": "ERROR", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)
    
    if _stop_scan_by_target(this.scans[scan_id] ['target_id']) is False:
        res.update({"status": "error",
        "reason": f"scan_id {scan_id} stop failed"})
        return jsonify(res)
    # 更新任务中status
    this.scans[scan_id] ['status'] = 'ABORTED'
    res.update({"status": "ABORTED"})
    return jsonify(res)


# Status of awvs engine(including status scanner and scans)
@app.route('/engines/awvs/status', methods=['GET'])
def status():
    res = {"page": "status"}
    # display the status of the scanner
    this.scanner['status'] = json.loads(info().get_data().decode("utf-8"))['status']
    res.update({"status": this.scanner['status']})

    # display info on the scanner
    res.update({"scanner": this.scanner})

    # display the status of scans performed
    scans = {}
    for scan in this.scans.keys():
        scan_status(scan)
    res.update({"scans": this.scans})

    return jsonify(res)


@app.route('/engines/awvs/status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    res = {"page": "scan_status"}

    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": "scan_id '{}' not found".format(scan_id)})
        return jsonify(res)

    # check id the scan is finished or not
    # target_scan_list = _get_awvs_scan_id(this.scans[scan_id]['target_id'])
    # raise Exception(target_scan_list)

    try:
        target_scan_list = _get_awvs_scan_id(this.scans[scan_id]['target_id'])
        if target_scan_list is None:
            raise NameError
        target_scan_list = target_scan_list['scans']
        if len(target_scan_list) == 0:
            raise IndexError
        latest_awvs_scan = target_scan_list[0]
        if latest_awvs_scan['current_session']['status'] == 'completed':
            this.scans[scan_id]["status"] = "FINISHED"
            this.scans[scan_id]["finished_at"] = datetime.datetime.now()
        else:
            this.scans[scan_id]["status"] = str(latest_awvs_scan['current_session']['status']).upper()
    except IndexError:
        this.scans[scan_id]["status"] = "ERROR"
        res.update({"status": "ERROR",	"reason": "no scans start"})
    except NameError:
        this.scans[scan_id]["status"] = "ERROR"
        res.update({"status": "ERROR",	"reason": "API:_get_awvs_scan_id error"})
    except Exception as error:
        raise Exception(error)
        this.scans[scan_id]["status"] = "ERROR"
        res.update({"status": "ERROR",	"reason": "API error"})
    
    res.update({
        "scan": this.scans[scan_id],
        "status": this.scans[scan_id]["status"]
    })

    return jsonify(res)


@app.route('/engines/awvs/info')
def info():
    res = {"page": "info"}

    r = None
    try:
        api_url = f"{this.scanner['api_url_']}/info"
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }
        r = requests.get(url=api_url, headers=headers, verify=False)
        if r.status_code == 200:
            res.update({
                "status": "READY",
                "engine_config": this.scanner
            })
        else:
            res.update({"status": "ERROR", "details": {
                "engine_config": this.scanner}})
    except Exception:
        res.update({"status": "ERROR", "details": "connexion error to the API {}".format(api_url)})

    return jsonify(res)


@app.route('/engines/awvs/getfindings/<scan_id>')
def getfindings(scan_id):

    res = {"page": "getfindings"}

    if not _is_scan_finished(scan_id):
        res.update({"status": "ERROR", "reason": "scan '{}' not finished".format(scan_id)})
        return jsonify(res)

    # res要素1————scans
    scan = {"scan_id": scan_id}
    res.update({"scan": scan})

    # res要素2————summary
    summary = _get_statistics(this.scans[scan_id]['target_id'])['severity_counts']
    res.update({"summary": summary})

    # res要素3————issues
    issues = _get_all_vulninfo(this.scans[scan_id]['target_id'])
    res.update({"issues": issues})

    # res要素4————status
    res.update({"status": "success"})
     
    # Store the findings in a file
    with open(BASE_DIR+"/results/awvs_"+str(scan_id)+".json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues,
            "status": "success"
        }, report_file, default=_json_serial)
    
    # remove the scan from the active scan list
    clean_scan(scan_id)

    return jsonify(res)


@app.route('/engines/awvs/getreport', methods=['GET'])
def getreport(scan_id):
    filepath = BASE_DIR+f"/results/awvs_{scan_id}.json"

    if not os.path.exists(filepath):
        return jsonify({"status": "ERROR", "reason": "report file for scan_id '{}' not found".format(scan_id)})
    
    return send_from_directory(BASE_DIR+"/results/", "awvs_"+scan_id+".json")



@app.route('/engines/awvs/test')
def test():
    if not APP_DEBUG:
        return jsonify({"page": "test"})
    
    res = "<h2>Test Page (DEBUG):</h2>"
    for rule in app.url_map.iter_rules():
        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        methods = ','.join(rule.methods)
        url = url_for(rule.endpoint, **options)
        res += urlparse.unquote("{0:50s} {1:20s} <a href='{2}'>{2}</a><br/>".format(rule.endpoint, methods, url))

    return res


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"page": "not found"})


@app.before_first_request
def main():
    if not os.path.exists(BASE_DIR+"/results"):
        os.makedirs(BASE_DIR+"/results")
    if not os.path.exists(BASE_DIR+"/logs"):
        os.makedirs(BASE_DIR+"/logs")
    loadconfig()


# 开启扫描，对应AWVS中Scans API中的schedule_scan
def _start_scan(target_id,profile_id="11111111-1111-1111-1111-111111111111"):
    r = None
    try:
        api_url = f"{this.scanner['api_url_']}/scans"
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }
        values = {
            'target_id': target_id,
            'profile_id': profile_id,
            "schedule":
                {"disable":False,
                "start_date":None,
                "time_sensitive":False
                }
        }
        data = bytes(json.dumps(values), 'utf-8')
        r = requests.post(url=api_url, headers=headers, data=data, verify=False)
        return r
    except Exception:
        return None

# 添加AWVS target————添加多个target需要传groups参数，暂时一个扫描任务只扫一个target
def _add_target(address, description='asset_types:url', criticality=10):
    r = None
    try:
        api_url = f"{this.scanner['api_url_']}/targets"
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }
        values = {
            'address': address,
            'description': description,
            'criticality': criticality
        }
        data = bytes(json.dumps(values), 'utf-8')
        r = requests.post(url=api_url, headers=headers, data=data, verify=False)
        if r.status_code in SUCCESS_RES:
            return r.json()
        else:
            return None
    except Exception:
        return None


# Returns all AWVS Targets.
def _get_target_list():
    r = None
    try:
        api_url = f"{this.scanner['api_url_']}/targets"
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }
        r = requests.get(url=api_url, headers=headers, verify=False)
        if r.status_code in SUCCESS_RES:
            return r.json()
        else:
            return None
    except Exception:
        return None


# 删除某个target
def _delete_taget(target_id):
    try:
        api_url = f"{this.scanner['api_url_']}/targets/{target_id}"
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }
        r = requests.delete(url=api_url, headers=headers, verify=False)
        if r.status_code in SUCCESS_RES:
            return True
        else:
            return False
    except Exception:
        return False


# 删除所有的targets
def _delete_all_tatgets():
    targets_list = _get_target_list()
    if targets_list is None:
        return False
    if len(targets_list) == 0:
        return True
    targets_list = targets_list['targets']
    for target in targets_list:
        if _delete_taget(target['target_id']) is False:
            return False
    return True


# 根据target_id查询所有对应的scans
def _get_awvs_scan_id(target_id):
    try:
        api_url = f"{this.scanner['api_url_']}/scans?q=target_id:{target_id}"
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }
        r = requests.get(url=api_url, headers=headers, verify=False)
        if r.status_code == 200:
            return r.json()
        else:
            return None
    except Exception:
        return None


# 暂停某个扫描任务
def _stop_awvs_scan_id(awvs_scan_id):
    try:
        api_url = f"{this.scanner['api_url_']}/scans/{awvs_scan_id}/abort"
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }
        r = requests.post(url=api_url, headers=headers, verify=False)
        if r.status_code == 204 or 409:
            return True
        else:
            return False
    except Exception:
        return False


# 因为target是通过target_id区分的，因此相同的target内容也会有不同的target_id，而一个扫描中只有1个target，所以对target的操作基本映射到对应的scan上
# 暂停某target_id对应的scan
def _stop_scan_by_target(target_id):
    target_scan_list = _get_awvs_scan_id(target_id)
    if target_scan_list is None:
        return False
    target_scan_list = target_scan_list['scans']
    if len(target_scan_list) == 0:
        return True
    target_scan_list = [i['scan_id'] for i in target_scan_list]
    for awvs_scan_id in target_scan_list:
        if _stop_awvs_scan_id(awvs_scan_id) is False:
            return False
    return True


# 暂停awvs所有的scans
def _stop_all_scans():
    targets_list = _get_target_list()['targets']
    if targets_list is None:
        return False
    if len(targets_list) == 0:
        return True
    for target in targets_list:
        if _stop_scan_by_target(target['target_id']) is False:
            return False
    return True


# Returns all AWVS Scans.
def _get_scan_list():
    r = None
    try:
        api_url = f"{this.scanner['api_url_']}/scans"
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }
        r = requests.get(url=api_url, headers=headers, verify=False)
        if r.status_code in SUCCESS_RES:
            return r.json()
        else:
            return None
    except Exception:
        return None


# 删除某个awvs scan
def _delete_scan(scan_id):
    try:
        api_url = f"{this.scanner['api_url_']}/scans/{scan_id}"
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }
        r = requests.delete(url=api_url, headers=headers, verify=False)
        if r.status_code in SUCCESS_RES:
            return True
        else:
            return False
    except Exception:
        return False


# 根据target_id删除对应的scan
def _delete_scan_by_target(target_id):
    target_scan_list = _get_awvs_scan_id(target_id)
    if target_scan_list is None:
        return False
    target_scan_list = target_scan_list['scans']
    if len(target_scan_list) == 0:
        return True
    target_scan_list = [i['scan_id'] for i in target_scan_list]
    for awvs_scan_id in target_scan_list:
        if _delete_scan(awvs_scan_id) is False:
            return False
    return True


# 删除awvs所有的scan
def _delete_all_scans():
    targets_list = _get_target_list()
    if targets_list is None:
        return False
    if len(targets_list) == 0:
        return True
    targets_list = targets_list['targets']
    for target in targets_list:
        target_scan_list = _get_awvs_scan_id(target['target_id'])
        if target_scan_list is None:
            return False
        target_scan_list = target_scan_list['scans']
        if len(target_scan_list) == 0:
            return True
        target_scan_list = [i['scan_id'] for i in target_scan_list]
        for awvs_scan_id in target_scan_list:
            if _delete_scan(awvs_scan_id) is False:
                return False
        return True
    return True


def _is_scan_finished(scan_id):
    if scan_id not in this.scans.keys():
        app.logger.error("scan_id {} not found".format(scan_id))
        return False
    
    if this.scans[scan_id]["status"] in ["FINISHED", "STOPPED"]:
        return True

    return False


# 查询target_id对应的scan的结果的统计信息————summary
def _get_statistics(target_id):
    target_scan_list = _get_awvs_scan_id(target_id)
    latest_awvs_scan = target_scan_list['scans'][0]
    try:
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }      
        api_url = f"{this.scanner['api_url_']}/scans/{latest_awvs_scan['scan_id']}/results/{latest_awvs_scan['current_session']['scan_session_id']}/statistics"
        r = requests.get(url=api_url, headers=headers, verify=False)
        if r.status_code == 200:
            return r.json()
        else:
            return None
    except Exception as e:
        print(e)
        return None


# 查询target_id对应的scan的结果的全部漏洞信息（不包括漏洞详情）
# cursor设置从0开始，limit最大是1000，默认单个url的最多漏洞为1000，应该够了
def _get_scan_vulns(target_id, c=0, l=1000): 
    target_scan_list = _get_awvs_scan_id(target_id)
    latest_awvs_scan = target_scan_list['scans'][0]
    try:
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }      
        api_url = f"{this.scanner['api_url_']}/scans/{latest_awvs_scan['scan_id']}/results/{latest_awvs_scan['current_session']['scan_session_id']}/vulnerabilities?c={c}&l={l}"
        r = requests.get(url=api_url, headers=headers, verify=False)
        if r.status_code == 200:
            return r.json()
        else:
            return None
    except Exception as e:
        print(e)
        return None


# 查询单个漏洞的详细信息
def _get_single_vulninfo(target_id, vuln_id):
    target_scan_list = _get_awvs_scan_id(target_id)
    latest_awvs_scan = target_scan_list['scans'][0]
    try: 
        headers = {
            'X-Auth': f"{this.scanner['api_key']}",
            'Content-type': 'application/json'
        }       
        api_url = f"{this.scanner['api_url_']}/scans/{latest_awvs_scan['scan_id']}/results/{latest_awvs_scan['current_session']['scan_session_id']}/vulnerabilities/{vuln_id}"
        r = requests.get(url=api_url, headers=headers, verify=False)
        if r.status_code == 200:
            return r.json()
        else:
            return None
    except Exception as e:
        print(e)
        return None


# 查询一个扫描的全部漏洞信息————issuss
def _get_all_vulninfo(target_id):

    # 查询扫描的target url
    target_scan_list = _get_awvs_scan_id(target_id)
    scan_url = target_scan_list['scans'][0]['target']['address']

    issues = list()
    # 遍历所有的vuln
    all_vulns = _get_scan_vulns(target_id)['vulnerabilities']
    for vuln in all_vulns:   
        # 查询漏洞详情
        vuln_detail = _get_single_vulninfo(target_id,vuln['vuln_id'])

        # 构造description————affects_url+raw_description+impact
        affects_url = vuln_detail['affects_url'] if 'affects_url' in vuln_detail else ""
        raw_description = vuln_detail['description'] if 'description' in vuln_detail else ""
        impact = vuln_detail['impact'] if 'impact' in vuln_detail else ""
        description = "affects url: "+affects_url+"\n\n\n"+raw_description+"\n\n\nimpact: "+impact  
        
        # 构造issue
        issus = {
            "severity": value_to_level.get(int(vuln_detail['severity'])) if 'severity' in vuln_detail else "",
            "confidence": vuln_detail['confidence'] if 'confidence' in vuln_detail else "",
            "metadata": {
                "risk": {
                    "cvss_base_score": vuln_detail['cvss_score'] if 'cvss_score' in vuln_detail else {}
                },
                "vuln_refs": {},
                "links": vuln_detail['references'] if 'references' in vuln_detail else [],
                "tags": vuln_detail['tags'] if 'tags' in vuln_detail else []
            },
            "title": vuln_detail['vt_name'] if 'vt_name' in vuln_detail else "",
            "type": vuln_detail['impact'][0:1023] if 'impact' in vuln_detail else "", # 此处需要改数据库findings/type字段的大小，改为1024
            "solution": vuln_detail['recommendation'] if 'recommendation' in vuln_detail else ""
        }
        
        # 构造raw————details+request
        element_details = vuln_detail['details'] if 'details' in vuln_detail else ""
        element_request = vuln_detail['request'] if 'request' in vuln_detail else ""
        raw = {
            "details": element_details,
            "request": element_request
        }
        issus['raw'] = raw
        issus['description'] = description
        
        # 构造target
        target = {
            "addr": [scan_url]
        }
        issus['target'] = target
        
        issues.append(issus)
    
    return issues
    

def _json_serial(obj):
    """
        JSON serializer for objects not serializable by default json code
        Used for datetime serialization when the results are written in file
    """

    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="Hostname of the Flask app [default %s]" % APP_HOST, default=APP_HOST)
    parser.add_option("-P", "--port", help="Port for the Flask app [default %s]" % APP_PORT, default=APP_PORT)
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP)
    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port), threaded=True)
