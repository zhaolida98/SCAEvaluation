import csv
import os
import subprocess
import time
import traceback

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

def batch_mvn_build(manifest_csv):
    result_csv = open("/root/SCAEvaluation/testsuite2/install_status.csv", 'a+')
    fieldnames = ['name','status', 'error_log']
    csv_writer = csv.DictWriter(result_csv, fieldnames)
    csv_writer.writeheader()
    csv_reader = csv.DictReader(manifest_csv)
    for row in csv_reader:
        scan_type = row['type']
        target_name = row['target']
        workding_dir = row['working_path']
        status_record_dict = {
                'name': target_name,
                'status': "success",
                'error_log': ''
            }
        full_target_path = os.path.join(workding_dir, target_name)
        cmd = f'cd {full_target_path} && mvn install -Dmaven.test.skip'
        print(f"executing {cmd}")
        res = exec_command(cmd)
        if res.get('code') != 0:
            status_record_dict['status'] = 'failed'
        csv_writer.writerow(status_record_dict)
    manifest_csv.close()

if __name__ == '__main__':
    manifest_csv_path = f"/root/SCAEvaluation/testsuite2/manifest-testsuite2.csv"
    manifest_csv = open(manifest_csv_path, 'r')
    batch_mvn_build(manifest_csv)
