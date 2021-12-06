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

def batch_generate_mvn_gt(manifest_csv):
    csv_reader = csv.DictReader(manifest_csv)
    for row in csv_reader:
        scan_type = row['type']
        target_name = row['target']
        workding_dir = row['working_path']

        report_path = os.path.join(workding_dir, scan_type+'_report')
        full_target_path = os.path.join(workding_dir, target_name)
        dep_tree_txt = f"{full_target_path}/dep.txt"

        cmd = f'cd {full_target_path} && mvn clean dependency:tree > {dep_tree_txt}'
        pretty_log(f"executing {cmd}")
        res = exec_command(cmd)
        if res.get('code') != 0:
            if 'output' in res:
                pretty_log(res['output'].decode(), 'ERROR')
            if 'error' in res:
                pretty_log(res['error'].decode(), 'ERROR')
            raise RuntimeError("generate dependency:tree error. Make sure the project can be built")
        
        cmd = f'python generate_mvn_gt.py {dep_tree_txt} {report_path} {target_name}'
        pretty_log(f"executing {cmd}")
        res = exec_command(cmd)
        if res.get('code') != 0:
            if 'output' in res:
                pretty_log(res['output'].decode(), 'ERROR')
            if 'error' in res:
                pretty_log(res['error'].decode(), 'ERROR')
            raise RuntimeError("parsing dependency:tree output error")

    manifest_csv.close()

if __name__ == '__main__':
    manifest_csv_path = f"/root/SCAEvaluation/testsuite1/manifest-testsuite1.csv"
    manifest_csv = open(manifest_csv_path, 'r')
    batch_generate_mvn_gt(manifest_csv)
