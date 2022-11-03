import csv
import os
import json

def check_summary_json(summary_json_path, project_name, report_folder,tool):

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
    testsuite_path = "/home/lida/SCAEvaluation-main/large_scale/reports"
    manifest_csv_path = f"/home/lida/SCAEvaluation-main/large_scale/manifest/build_manifest.csv"
    project_names = []
    with open(manifest_csv_path, 'r') as manifest_csv:
        csv_reader = csv.DictReader(manifest_csv)
        project_names = [i['target'] for i in csv_reader]
    print(len(project_names))

    report_folder_names = ["build", 'prebuild']
    comparatee_list = ['owasp', 'scantist', 'steady', 'ossindex', 'dependabot', 'snyk']
    fields = ["report_type","project_name","tool","cmpt_tp","cmpt_fn","cmpt_fp","cve_tp","cve_fn","cve_fp"]
    output_csv = []
    cnt = 0
    for report_folder in report_folder_names:
        for project_name in project_names:
            for comparatee in comparatee_list:
                summary_name = f"groundtruth-{comparatee}-summary.json"
                report_path = os.path.join(testsuite_path, project_name, report_folder,summary_name)
                print(f"start processing: {report_folder}: {project_name}: {comparatee}")
                cnt += 1
                if not os.path.isfile(report_path):
                    continue
                tmp_json = check_summary_json(report_path, project_name, report_folder,comparatee)
                output_csv.append(tmp_json)
    with open("help_me_read.csv", "w") as f:
        csv_writer = csv.DictWriter(f, fieldnames=fields)
        csv_writer.writeheader()
        csv_writer.writerows(output_csv)

    