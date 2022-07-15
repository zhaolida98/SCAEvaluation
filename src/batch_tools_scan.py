import csv
import os
import subprocess
import time
import traceback

manifest_csv_path = f"/root/SCAEvaluation/testsuite2/manifest-testsuite2.csv"
status_csv_path = "/root/SCAEvaluation/testsuite2/status.csv"

def pretty_log(log, logtype="INFO"):
    print(f'[{logtype}] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}| {log}')


def exec_command(cmd, work_dir="."):
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=work_dir
    )
    return_code = 0
    try:
        out, err = p.communicate()
        return_code = p.returncode
        if err:
            return {"error": err, "output": out.strip(), "code": return_code}
    except Exception as e:
        return {"error": traceback.format_exc(), "code": return_code}
    return {"output": out.strip(), "code": return_code}


def batch_tools_scan(manifest_csv, source_waiting_tools, saas_waiting_tools):
    result_csv = open(status_csv_path, 'a+')
    fieldnames = ['name', 'tool','status', 'time', 'error_log']
    csv_writer = csv.DictWriter(result_csv, fieldnames)
    csv_writer.writeheader()
    csv_reader = csv.DictReader(manifest_csv)
    for row in csv_reader:
        scan_type = row['type']
        target_name = row['target']
        workding_dir = row['working_path']
        print(f"****************processing {scan_type} {target_name}****************")
        scan_method = ""
        waiting_tools = []
        if row['type'] == 'source':
            scan_method = 'cmd'
            waiting_tools = source_waiting_tools
            full_target_path = os.path.join(workding_dir, target_name)
        elif row['type'] == 'saas':
            scan_method = 'cmd'
            waiting_tools = saas_waiting_tools
            full_target_path = os.path.join(workding_dir, target_name)
        else:
            pretty_log(f"batch scan will skip {row['type']}")
            continue

        report_path = os.path.join(workding_dir, scan_type+'_report')
        # trigger scan
        for tool in waiting_tools:
            status_record_dict = {
                'name': target_name,
                'tool': tool,
                'time': 0,
                'status': "success",
                'error_log': ''
            }
            timer_start = time.time()
            cmd = f"karby {tool} {scan_method} {full_target_path} -name {target_name} -output {report_path}"
            pretty_log(f"executing {cmd}")
            res = exec_command(cmd)
            status_record_dict['time'] = time.time() - timer_start
            if res.get('code') != 0:
                status_record_dict['status'] = 'failed'
                if 'output' in res:
                    pretty_log(res['output'].decode(), 'ERROR')
                    # status_record_dict['error_log'] += res['output'].decode()
                if 'error' in res:
                    pretty_log(res['error'].decode(), 'ERROR')
                    # status_record_dict['error_log'] += res['error'].decode()
            
            csv_writer.writerow(status_record_dict)
    manifest_csv.close()
    result_csv.close()


if __name__ == '__main__':
    manifest_csv = open(manifest_csv_path, 'r')
    #['scantist', 'whitesource', 'owasp', 'steady', 'dependabot']
    source_waiting_tools = ['scantist']
    saas_waiting_tools = []
    batch_tools_scan(manifest_csv, source_waiting_tools, saas_waiting_tools)
