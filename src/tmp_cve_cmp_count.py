import csv
import os
import json
from timeit import repeat

def check_summary_json(summary_json_path, project_name, report_folder,tool):
    print(summary_json_path)
    with open(summary_json_path, 'r') as f:
        content = f.read()
        content_json = json.loads(content) 
        tmp_json = {
            "report_type":report_folder,
            "project_name":project_name,
            "tool":tool,
            "cmpt_tp":0,
            "cmpt_fn":0,
            "cmpt_fp":0,
            "cve_tp":0,
            "cve_fn":0,
            "cve_fp":0
        }
        if content_json['report_per_case'][0]['component_report']:
            tmp_json['cmpt_tp'] = content_json['report_per_case'][0]['component_report']['tplv_tp_cnt']
            tmp_json['cmpt_fn'] = content_json['report_per_case'][0]['component_report']['tplv_fn_cnt']
            tmp_json['cmpt_fp'] = content_json['report_per_case'][0]['component_report']['tplv_fp_cnt']
        if 'issue_report' in content_json['report_per_case'][0] \
            and content_json['report_per_case'][0]['issue_report']\
            and 'gav_cve_tp_cnt' in content_json['report_per_case'][0]['issue_report']:
            tmp_json['cve_tp'] = content_json['report_per_case'][0]['issue_report']['gav_cve_tp_cnt']
            tmp_json['cve_fn'] = content_json['report_per_case'][0]['issue_report']['gav_cve_fn_cnt']
            tmp_json['cve_fp'] = content_json['report_per_case'][0]['issue_report']['gav_cve_fp_cnt']
        return tmp_json

if __name__ == '__main__':
    testsuite_path = "/root/SCAEvaluation/testsuite2"
    project_names = os.listdir(testsuite_path)
    report_folder_names = ["intersect_report"]
    comparatee_list = ['groundtruth']
    cmp_set = set()
    cve_set = set()
    for report_folder in report_folder_names:
        for project_name in project_names:
            if project_name.endswith("csv"):
                continue
            for comparatee in comparatee_list:
                groundtruth_csv = f'groundtruth-component-{project_name}.csv'
                report_path = os.path.join(testsuite_path, project_name, report_folder,groundtruth_csv)
                # if not os.path.isfile(report_path):
                    # continue
                with open(report_path, 'r') as f:
                    for line in f.readlines():
                        tmp = line.split(',')
                        lib = f"{tmp[0]}:{tmp[2]}"
                        cmp_set.add(lib)
                groundtruth_csv = f'groundtruth-issue-{project_name}.csv'
                report_path = os.path.join(testsuite_path, project_name, report_folder,groundtruth_csv)
                # if not os.path.isfile(report_path):
                #     continue
                with open(report_path, 'r') as f:
                    for line in f.readlines():
                        tmp = line.split(',')
                        lib = f"{tmp[2]}"
                        cve_set.add(lib)
    print(len(cmp_set))
    print(len(cve_set))