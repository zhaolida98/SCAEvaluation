import csv
import os
import subprocess
import traceback


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

test_suit_dir = "/root/SCAEvaluation/testsuite2"
collection_csv_path = '/root/SCAEvaluation/testsuite2/collection-testsuite2.csv'
collection_csv = open(collection_csv_path, 'r')
manifest_csv_path = '/root/SCAEvaluation/testsuite2/manifest-testsuite2.csv'
manifest_csv = open(manifest_csv_path, 'a+')
reader = csv.DictReader(collection_csv)
writer = csv.DictWriter(manifest_csv, ['type', 'target', 'working_path'])
writer.writeheader()

for cnt, item in enumerate(reader):
    raw_name = item['name']
    name = raw_name.replace('/', '@')
    print(f"processing on {raw_name}, cnt: {cnt}")
    proj_working_dir = os.path.join(test_suit_dir, name)
    if not os.path.isdir(proj_working_dir):
        os.mkdir(proj_working_dir)
    if not os.path.isdir(os.path.join(proj_working_dir, name)):
        cmd = f"cd {proj_working_dir} && git clone https://github.com/{raw_name}.git {name}"
        res = exec_command(cmd)
        if res.get('code') != 0:
            print(f"\nclone {raw_name} failed")
    tmp_item = {
        'type': 'source',
        'target': name,
        'working_path': proj_working_dir
    }
    writer.writerow(tmp_item)
collection_csv.close()
manifest_csv.close()



