import csv
import os

from util.utils import pretty_log, exec_command


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
    manifest_csv_path = f"/manifest-test.csv"
    manifest_csv = open(manifest_csv_path, 'r')
    batch_generate_mvn_gt(manifest_csv)
