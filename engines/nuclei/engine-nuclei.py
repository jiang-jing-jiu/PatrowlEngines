#!/usr/bin/python3
# -*- coding: utf-8 -*-
import datetime
import json
import optparse
import os
import re
import subprocess
import sys
import threading
import time
import urllib
from copy import deepcopy
from shlex import split

import psutil
from flask import (Flask, jsonify, redirect, request, send_from_directory,
                   url_for)

app = Flask(__name__)
APP_DEBUG = os.environ.get('DEBUG', '').lower() in ['true', '1', 'yes', 'y', 'on']
APP_HOST = "0.0.0.0"
APP_PORT = 5016
APP_MAXSCANS = int(os.environ.get('APP_MAXSCANS', 5))
APP_SCAN_TIMEOUT_DEFAULT = int(os.environ.get('APP_SCAN_TIMEOUT_DEFAULT', 7200))

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
this = sys.modules[__name__]
this.scanner = {}
this.scan_id = 1
this.scans = {}

# Generic functions
def _json_serial(obj):
    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")

# Route actions
@app.route('/')
def default():
    """Handle default route."""
    return redirect(url_for('index'))


@app.route('/engines/nuclei/')
def index():
    """Handle index route."""
    return jsonify({"page": "index"})

def loadconfig():
    """Load configuration from local file."""
    conf_file = f"{BASE_DIR}/nuclei.json"
    if os.path.exists(conf_file):
        json_data = open(conf_file)
        this.scanner = json.load(json_data)
        this.scanner['status'] = "READY"
    else:
        this.scanner['status'] = "ERROR"
        return {"status": "ERROR", "reason": "config file not found."}
    if not os.path.isfile(this.scanner['path']):
        this.scanner['status'] = "ERROR"
        return {"status": "ERROR", "reason": "path to nuclei binary not found."}

    version_filename = f"{BASE_DIR}/VERSION"
    if os.path.exists(version_filename):
        version_file = open(version_filename, "r")
        this.scanner["version"] = version_file.read().rstrip('\n')
        version_file.close()

@app.route('/engines/nuclei/startscan', methods=['POST'])
def start():
    res = {"page": "startscan"}

    # check the scanner is ready to start a new scan
    if len(this.scans) >= APP_MAXSCANS + 1:
        res.update({
            "status": "error",
            "reason": f"Scan refused: max concurrent active scans reached ({APP_MAXSCANS})"
        })
        return jsonify(res), 503

    # update scanner status
    status()

    if this.scanner['status'] != "READY":
        res.update({
            "status": "refused",
            "details": {
                "reason": "scanner not ready",
                "status": this.scanner['status']
            }})
        return jsonify(res), 503

    # Load scan parameters
    data = json.loads(request.data.decode("UTF-8"))
    if 'assets' not in data.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": "arg error, something is missing ('assets' ?)"
            }})
        return jsonify(res), 500

    scan_id = str(data['scan_id'])
    if data['scan_id'] in this.scans.keys():
        res.update({
            "status": "refused",
            "details": {
                "reason": f"scan '{data['scan_id']}' already launched",
            }})
        return jsonify(res), 503

    if type(data['options']) == str:
        data['options'] = json.loads(data['options'])

    scan = {
        'assets': data['assets'],
        'futures': [],
        'threads': [],
        'proc': None,
        'options': data['options'],
        'scan_id': scan_id,
        'status': "STARTED",
        'issues_available': False,
        'started_at': int(time.time() * 1000),
        'nb_findings': 0
    }

    this.scans.update({scan_id: scan})
    th = threading.Thread(target=_scan_thread, args=(scan_id,))
    th.start()
    this.scans[scan_id]['threads'].append(th)

    res.update({
        "status": "accepted",
        "details": {"scan_id": scan['scan_id']}
    })

    return jsonify(res)


def _scan_thread(scan_id):
    hosts = []

    for asset in this.scans[scan_id]['assets']:
        if asset["datatype"] not in this.scanner["allowed_asset_types"]:
            return jsonify({
                "status": "refused",
                "details": {
                    "reason": f"datatype '{asset['datatype']}' not supported for the asset {asset['value']}."
                }})
        else:
            hosts.append(asset["value"].strip())

    # ensure no duplicates
    hosts = list(set(hosts))

    # write hosts in a file (cleaner and doesn't break with shell arguments limit (for thousands of hosts)
    hosts_filename = f"{BASE_DIR}/tmp/engine_nuclei_hosts_{scan_id}.tmp"
    with open(hosts_filename, 'w') as hosts_file:
        for item in hosts:
            hosts_file.write("%s\n" % item)
            app.logger.debug('asset: %s', item)

    # Sanitize args :
    options = this.scans[scan_id]['options'] or {}
    app.logger.debug('options: %s', options)
    args = options.get("args") or []

    cmd = f" {this.scanner['path']} -l {hosts_filename} "
    # -t /path/to/templates  指定模板。
    # 默认使用 http 请求下的 cves 模板。
    cmd += " ".join(args)
    cmd += " -o " + f"{BASE_DIR}/results/nuclei_{scan_id}.xml"
    app.logger.debug('cmd: %s', cmd)
    print(cmd)
    cmd_sec = split(cmd)
    this.scans[scan_id]["proc_cmd"] = "not set!!"
    this.scans[scan_id]["proc"] = subprocess.Popen(
        cmd_sec,
        shell=False,
        stdout=open("/dev/null", "w"), stderr=open("/dev/null", "w")
    )

    this.scans[scan_id]["proc_cmd"] = cmd
    proc = this.scans[scan_id]["proc"]

    # Define max timeout
    max_timeout = APP_SCAN_TIMEOUT_DEFAULT
    timeout = time.time() + max_timeout
    while time.time() < timeout:
        if (
            hasattr(proc, 'pid')
            and psutil.pid_exists(proc.pid)
            and psutil.Process(proc.pid).status() in ["sleeping", "running"]
        ):
            # Scan is still in progress
            time.sleep(3)
            print(f'scan {scan_id} still running...')
        else:
            # Scan is finished
            print(f'scan {scan_id} is finished !')
            break

    # Check if the report is available (exists && scan finished)
    report_filename = f"{BASE_DIR}/results/nuclei_{scan_id}.xml"
    if not os.path.exists(report_filename):
        this.scans[scan_id]["status"] = "FINISHED"  # ERROR ?
        this.scans[scan_id]["issues_available"] = True
        return False
    try:
        issues = _parse_report(report_filename, scan_id)
        this.scans[scan_id]["issues"] = deepcopy(issues)
    except Exception:
        pass
    this.scans[scan_id]["issues_available"] = True
    this.scans[scan_id]["status"] = "FINISHED"

    return True


"""
[waf-detect:apachegeneric] [http] [info] http://10.10.33.204:8081/
[jmx-default-login] [http] [high] http://10.10.33.204:8081/jmx-console/ [pass="admin",user="admin"]

_ret = re.findall(r"\[(.*?)\]", line)
_ret = [
    "waf-detect:apachegeneric",
    "http",
    "info",
]
_ret = [
    "jmx-default-login",
    "http",
    "high",
    'pass="admin",user="admin"',
]
"""


ALL_LEVEL = ["info", "low", "medium", "high", "critical"]


def _parse_report(filename, scan_id):
    """Parse the nuclei report."""
    res = []

    with open(filename, 'r') as f:
        for line in f.readlines():
            _ret = re.findall(r"\[(.*?)\]", line)
            _addr = re.sub(r"\[(.*?)]", "", line)
            _addr = _addr +'[ '+ _ret[len(_ret)-1] + ' ]'
            addr = ''
            # 从nuclei执行文件中找当前结果对应的urls
            hosts_filename = f"{BASE_DIR}/tmp/engine_nuclei_hosts_{scan_id}.tmp"
            with open(hosts_filename, 'r') as urls:
                for url in urls.readlines():
                    # 如果url在检测结果详情_addr中
                    print(url.strip())
                    print(_addr)
                    if url.strip() in _addr:
                        addr = url
                        break
            if _ret:
                title = _ret[0]
                severity = (
                    _ret[2] if len(_ret) >= 3 and _ret[2] in ALL_LEVEL else ""
                )

                this.scans[scan_id]["nb_findings"] += 1
                _res = {
                    "severity": severity,
                    "confidence": "",
                    "metadata": {
                        "risk": {},
                        "vuln_refs": {},
                        "links": [],
                        "tags": [],
                    },
                    "type": "",
                    "solution": "",
                    "issue_id": this.scans[scan_id]["nb_findings"],
                    "title": title,
                    "target": {"addr": [addr]},  # addr: List
                    "raw": {"details": "", "request": ""},
                    "description": _addr,
                }
                res.append(_res)
    if not res:
        res.append({
            "severity": "info",
            "confidence": "",
            "metadata": {
                "risk": {},
                "vuln_refs": {},
                "links": [],
                "tags": [],
            },
            "type": "",
            "solution": "",
            "issue_id": this.scans[scan_id]["nb_findings"],
            "title": "验证未发现有关漏洞",
            "target": {"addr": [""]},  # addr: List
            "raw": {"details": "", "request": ""},
            "description": "",
        })
    return res


@app.route('/engines/nuclei/reloadconfig')
def reloadconfig():
    """Reload configuration route."""
    res = {"page": "reloadconfig"}
    loadconfig()
    res.update({"config": this.scanner})
    return jsonify(res)


@app.route('/engines/nuclei/clean')
def clean():
    res = {"page": "clean"}

    stop()
    this.scans.clear()
    loadconfig()
    res.update({"status": "SUCCESS"})
    return jsonify(res)


@app.route('/engines/nuclei/clean/<scan_id>')
def clean_scan(scan_id):
    res = {"page": "clean_scan"}
    res.update({"scan_id": scan_id})

    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res)

    stop_scan(scan_id)
    this.scans.pop(scan_id)
    res.update({"status": "removed"})
    return jsonify(res)


# Stop all scans
@app.route('/engines/nuclei/stopscans')
def stop():
    res = {"page": "stopscans"}

    for scan_id in this.scans.keys():
        stop_scan(scan_id)

    res.update({"status": "SUCCESS"})

    return jsonify(res)


@app.route('/engines/nuclei/stop/<scan_id>')
def stop_scan(scan_id):
    res = {"page": "stopscan"}

    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res)

    proc = this.scans[scan_id]["proc"]
    if hasattr(proc, 'pid'):
        # his.proc.terminate()
        # proc.kill()
        # os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        if psutil.pid_exists(proc.pid):
            psutil.Process(proc.pid).terminate()
        res.update({
            "status": "TERMINATED",
            "details": {
                "pid": proc.pid,
                "cmd": this.scans[scan_id]["proc_cmd"],
                "scan_id": scan_id}
        })

    this.scans[scan_id]['status'] = "STOPPED"
    this.scans[scan_id]['finished_at'] = int(time.time() * 1000)
    return jsonify(res)

@app.route('/engines/nuclei/status/<scan_id>')
def scan_status(scan_id):
    res = {"page": "status", "status": "SCANNING"}
    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res), 404

    if this.scans[scan_id]["status"] == "ERROR":
        res.update({"status": "error", "reason": "todo"})
        return jsonify(res), 503

    proc = this.scans[scan_id]["proc"]
    if not hasattr(proc, "pid"):
        res.update({"status": "ERROR", "reason": "No PID found"})
        return jsonify(res), 503

    # if not psutil.pid_exists(proc.pid):
    if not psutil.pid_exists(proc.pid) and this.scans[scan_id]["issues_available"] is True:
        res.update({"status": "FINISHED"})
        this.scans[scan_id]["status"] = "FINISHED"
        # print(f"scan_status/scan '{scan_id}' is finished")

    elif psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() in ["sleeping", "running"]:
        res.update({
            "status": "SCANNING",
            "info": {
                "pid": proc.pid,
                "cmd": this.scans[scan_id]["proc_cmd"]}
        })
        # print(f"scan_status/scan '{scan_id}' is still SCANNING")
    elif psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() == "zombie" and this.scans[scan_id]["issues_available"] is True:
        res.update({"status": "FINISHED"})
        this.scans[scan_id]["status"] = "FINISHED"
        psutil.Process(proc.pid).terminate()

    # print(scan_id, res['status'], psutil.pid_exists(proc.pid), hasattr(proc, "pid"), this.scans[scan_id]["issues_available"], psutil.Process(proc.pid).status())
    return jsonify(res)


@app.route('/engines/nuclei/status')
def status():
    res = {"page": "status"}
    if not os.path.exists(f'{BASE_DIR}/nuclei.json'):
        app.logger.error("nuclei.json config file not found")
        this.scanner['status'] = "ERROR"

    if 'path' in this.scanner:
        if not os.path.isfile(this.scanner['path']):
            app.logger.error("NUCLEI engine not found (%s)", this.scanner['path'])
            this.scanner['status'] = "ERROR"
    #
    # if len(this.scans) >= APP_MAXSCANS:
    #     this.scanner['status'] = "BUSY"
    # else:
    #     this.scanner['status'] = "READY"

    this.scanner['status'] = "READY"
    if len(this.scans) >= APP_MAXSCANS:
        # count nb started
        nb_started = 0
        for scan in this.scans.keys():
            if this.scans[scan]['status'] == 'SCANNING':
                nb_started += 1
        if nb_started >= APP_MAXSCANS:
            this.scanner['status'] = "BUSY"

    res.update({"status": this.scanner['status']})

    # display info on the scanner
    res.update({"scanner": this.scanner})

    # display the status of scans performed
    scans = {}
    for scan in this.scans.keys():
        scan_status(scan)
        scans.update({scan: {
            "status": this.scans[scan]["status"],
            "options": this.scans[scan]["options"],
            "nb_findings": this.scans[scan]["nb_findings"],
        }})
    res.update({"scans": scans})
    return jsonify(res)

@app.route('/engines/nuclei/info')
def info():
    scans = {}
    print(this.scans)
    for scan in this.scans.keys():
        scan_status(scan)
        scans.update({scan: {
            "status": this.scans[scan]["status"],
            "options": this.scans[scan]["options"],
            "nb_findings": this.scans[scan]["nb_findings"],
        }})

    res = {
        "page": "info",
        "engine_config": this.scanner,
        "scans": scans
    }
    return jsonify(res)


@app.route('/engines/nuclei/getfindings/<scan_id>')
def getfindings(scan_id):
    """Get findings from engine."""
    res = {"page": "getfindings", "scan_id": scan_id}
    if not scan_id.isdecimal():
        res.update({"status": "error", "reason": "scan_id must be numeric digits only"})
        return jsonify(res)
    if scan_id not in this.scans.keys():
        res.update({"status": "error", "reason": f"scan_id '{scan_id}' not found"})
        return jsonify(res)

    proc = this.scans[scan_id]["proc"]

    # check if the scan is finished
    status()
    if hasattr(proc, 'pid') and psutil.pid_exists(proc.pid) and psutil.Process(proc.pid).status() in ["sleeping", "running"]:
        res.update({"status": "error", "reason": "Scan in progress"})
        return jsonify(res)

    # check if the report is available (exists && scan finished)
    report_filename = BASE_DIR + "/results/nuclei_{}.xml".format(scan_id)
    if not os.path.exists(report_filename):
        res.update({"status": "error", "reason": "Report file not available"})
        return jsonify(res)

    if "issues" not in this.scans[scan_id].keys():
        res.update({"status": "error", "reason": "Issues not available yet"})
        return jsonify(res)

    issues = this.scans[scan_id]["issues"]
    scan = {
        "scan_id": scan_id
    }
    summary = {
        "nb_issues": len(issues),
        "nb_info": len(issues),
        "nb_low": 0,
        "nb_medium": 0,
        "nb_high": 0,
        "engine_name": "nuclei",
        "engine_version": this.scanner['version']
    }

    # Store the findings in a file
    with open(f"{BASE_DIR}/results/nuclei_{scan_id}.json", 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues,
            "status": "success",
        }, report_file, default=_json_serial)

    # Delete the tmp hosts file (used with -iL argument upon launching nuclei)
    hosts_filename = f"{BASE_DIR}/tmp/engine_nuclei_hosts_{scan_id}.tmp"
    if os.path.exists(hosts_filename):
        os.remove(hosts_filename)

    res.update({
        "scan": scan,
        "summary": summary,
        "issues": issues,
        "status": "success"
    })
    return jsonify(res)


@app.route('/engines/nuclei/getreport/<scan_id>')
def getreport(scan_id):
    if scan_id not in this.scans.keys():
        return jsonify({"status": "ERROR", "reason": f"scan_id '{scan_id}' not found"})

    # remove the scan from the active scan list
    clean_scan(scan_id)

    filepath = f"{BASE_DIR}/results/nuclei_{scan_id}.json"
    if not os.path.exists(filepath):
        return jsonify({"status": "ERROR", "reason": f"report file for scan_id '{scan_id}' not found"})

    return send_from_directory(
        f"{BASE_DIR}/results",
        f"nuclei_{scan_id}.json",
        mimetype='application/json',
        download_name=f"nuclei_{scan_id}.json",
        as_attachment=True
    )


@app.route('/engines/nuclei/test')
def test():
    res = "<h2>Test Page (DEBUG):</h2>"
    for rule in app.url_map.iter_rules():
        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        methods = ','.join(rule.methods)
        url = url_for(rule.endpoint, **options)
        res += urllib.request.url2pathname("{0:50s} {1:20s} <a href='{2}'>{2}</a><br/>".format(rule.endpoint, methods, url))

    return res


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"page": "not found"})


@app.before_first_request
def main():
    if os.getuid() != 0:
        app.logger.error("Start the NUCLEI engine using root privileges !")
#        sys.exit(-1)
    if not os.path.exists(f"{BASE_DIR}/results"):
        os.makedirs(f"{BASE_DIR}/results")
    if not os.path.exists(f"{BASE_DIR}/tmp"):
        os.makedirs(f"{BASE_DIR}/tmp")
    if not os.path.exists(f"{BASE_DIR}/logs"):
        os.makedirs(f"{BASE_DIR}/logs")
    loadconfig()


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="Hostname of the Flask app [default %s]" % APP_HOST, default=APP_HOST)
    parser.add_option("-P", "--port", help="Port for the Flask app [default %s]" % APP_PORT, default=APP_PORT)
    parser.add_option("-d", "--debug", action="store_true", dest="debug", help=optparse.SUPPRESS_HELP)

    options, _ = parser.parse_args()
    app.run(debug=options.debug, host=options.host, port=int(options.port))
