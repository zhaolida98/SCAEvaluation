import csv
import os
import shutil

import json
from threading import local
from generate_mvn_gt import generate_mvn_dep_tree_gt
from util.utils import pretty_log, exec_command
from util.depUtils import generate_dep_tree, generate_class_path

report_status_path = "/root/SCAEvaluation/large_scale/reports/report_status.json"
report_path = "/root/SCAEvaluation/large_scale/reports"
manifest_csv_path = "/root/SCAEvaluation/large_scale/projects/manifest.csv"

def batch_generate_mvn_gt(manifest_csv_path):
    manifest_csv = open(manifest_csv_path, 'r')
    csv_reader = csv.DictReader(manifest_csv)

    # status record
    report_status_json = {}
    if os.path.isfile(report_status_path):
        with open(report_status_path, 'r') as f:
            report_status_json = json.loads(f.read())
    

    try: 
        for idx, row in enumerate(csv_reader):
            pretty_log(f"batch_generate_mvn_gt | {idx}")
            dep_ok = True
            build_cp_ok = True
            generate_gt_ok = True
            local_name = row['local_name']
            working_dir = row['working_path']
            dep_tree_txt = f"{working_dir}/dep.txt"
            build_classpath_txt =  f"{working_dir}/classpath.txt"

            # if in cache and all failed, skip
            if local_name in report_status_json:
                continue

            # write dependency:tree to dep.txt
            if not (local_name in report_status_json and report_status_json[local_name]["dep_ok"] == True):
                dep_ok = generate_dep_tree(working_dir)
            
            # write dependency:class-buildpath to classpath.txt
            if not (local_name in report_status_json and report_status_json[local_name]["build_cp_ok"] == True):
                build_cp_ok = generate_class_path(working_dir)
            
            # calculate the ground truth by dep.txt and classpath.txt
            if build_cp_ok and dep_ok:
                if not (local_name in report_status_json and report_status_json[local_name]["generate_gt_ok"] == True):
                    generate_gt_ok = generate_mvn_dep_tree_gt(dep_tree_txt, build_classpath_txt, report_path, local_name)
            else:
                generate_gt_ok = False

            cur_status = {
                "dep_ok": dep_ok,
                "build_cp_ok": build_cp_ok,
                "generate_gt_ok": generate_gt_ok
            }
            report_status_json[local_name] = cur_status
    except Exception as e:
        pretty_log(e)
    finally:
        with open(report_status_path, 'w') as f:
            json.dump(report_status_json, f)
            pretty_log("process finished, saving report status json")
            manifest_csv.close()


if __name__ == '__main__':
    batch_generate_mvn_gt(manifest_csv_path)
