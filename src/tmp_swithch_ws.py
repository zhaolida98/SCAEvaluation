import csv
import os
import json

if __name__ == '__main__':
    testsuite_path = "/root/SCAEvaluation/testsuite1"
    project_names = os.listdir(testsuite_path)
    report_folder_names = ["source_report"]
    comparatee_list = ['whitesource']
    output_csv = []
    for report_folder in report_folder_names:
        for project_name in project_names:
            for comparatee in comparatee_list:
                if report_folder != "source_report":
                    continue
                ws_issue_report = f"{comparatee}-issue-{project_name}.csv.csv"
                report_path = os.path.join(testsuite_path, project_name, report_folder,ws_issue_report)
                if os.path.isfile(report_path):
                    os.remove(report_path)
    