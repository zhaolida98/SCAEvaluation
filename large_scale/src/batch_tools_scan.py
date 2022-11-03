import csv
import os
import subprocess
import time
import traceback
import multiprocessing
single_tool = 'scantist'
manifest_csv_path = "/home/lida/SCAEvaluation-main/large_scale/manifest/build_manifest.csv"
status_csv_path = f"/home/lida/SCAEvaluation-main/large_scale/manifest/{single_tool}_scan_status.csv"
report_root_path = "/home/lida/SCAEvaluation-main/large_scale/reports"
#['scantist', 'whitesource', 'owasp', 'steady', 'dependabot']
build_waiting_tools = [single_tool]
prebuild_waiting_tools = []

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

def record_scan_status(record_dict_list):
    fieldnames = ['name', 'tool','status', 'time', 'error_log']
    with open(status_csv_path, 'a+') as result_csv:
        csv_writer = csv.DictWriter(result_csv, fieldnames)
        csv_writer.writerows(record_dict_list)

def single_scan_project(row, cnt=0):
    write_rows = []
    scan_type = row['type']
    target_name = row['target']
    workding_dir = row['working_path']
    print(f"****************processing {cnt} {scan_type} {target_name}****************")
    scan_method = ""
    waiting_tools = []
    if row['type'] == 'build':
        scan_method = 'cmd'
        waiting_tools = build_waiting_tools
    elif row['type'] == 'prebuild':
        scan_method = 'upload'
        waiting_tools = prebuild_waiting_tools
    else:
        pretty_log(f"batch scan will skip {row['type']}")
        return write_rows

    report_path = os.path.join(report_root_path, target_name, scan_type)
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
        cmd = f"karby {tool} {scan_method} {workding_dir} -name {target_name} -output {report_path}"
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
        write_rows.append(status_record_dict)
        return write_rows


def batch_tools_scan(manifest_csv):
    name_cache = set()
    with open(status_csv_path, 'r') as f:
        for line in f.readlines():
            name = line.split(',')[0]
            name_cache.add(name)
    pool = multiprocessing.Pool(3)
    csv_reader = csv.DictReader(manifest_csv)
    for cnt, row in enumerate(csv_reader):
        target_name = row['target']

        if target_name in name_cache:
            continue

        pool.apply_async(func=single_scan_project, args=(row, cnt, ), callback=record_scan_status)
    pool.close()
    pool.join()

    # csv_reader = csv.DictReader(manifest_csv)
    # for cnt, row in enumerate(csv_reader):
    #     if cnt < 5:
    #         continue
    #     dicts = single_scan_project(row, cnt)
    #     record_scan_status(dicts)


if __name__ == '__main__':
    with open(manifest_csv_path, 'r') as manifest_csv:
        batch_tools_scan(manifest_csv)
