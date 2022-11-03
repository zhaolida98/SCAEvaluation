# cut the origin issue report and only remain the verified CVEs. named as {tool}-issue-{name}-verified.csv
import csv
from genericpath import isfile
from importlib.resources import contents
import os
import shutil
import json
from util.ComponentReport import ComponentReport
from util.IssueReport import IssueReport
from util.issueUtils import get_issue_list_with_cache
from util.utils import pretty_log, write_component_report, write_issue_report

report_path = "/home/lida/SCAEvaluation-main/large_scale/reports"
verified_cve = '/home/lida/SCAEvaluation-main/large_scale/cache/verified_cve.json'
verifeid_cve_set = None
with open(verified_cve, 'r') as f:
    content = json.load(f)
    verifeid_cve_set = content.keys()

tools = ['scantist', 'snyk', 'dependabot', 'owasp', 'steady', 'ossindex']
modes = ['build', 'prebuild']
def sum_reports():
    for idx, repo_name in enumerate(os.listdir(report_path)):
        print(f"processing on {repo_name}: {idx}")
        for mode in modes:
            build_repo_path = os.path.join(report_path, repo_name, mode)
            for tool in tools:
                issue_path = os.path.join(build_repo_path, f'{tool}-issue-{repo_name}.csv')
                if os.path.isfile(issue_path):
                    verified_issue_path = os.path.join(build_repo_path, f'{tool}-issue-{repo_name}-verified.csv')
                    verified_issue_list = []
                    with open(issue_path, 'r') as f:
                        with open(verified_issue_path, 'w') as k:
                            csvreader = csv.DictReader(f)
                            for i in csvreader:
                                if i['Public ID'] in verifeid_cve_set:
                                    verified_issue_list.append(i)
                            csvwriter = csv.DictWriter(k, ['Library','Library Version','Public ID','Scope','Score','File Path','Patched Version','Latest Component Version','Issue Source'])
                            csvwriter.writeheader()
                            csvwriter.writerows(verified_issue_list)
                            print('write', verified_issue_path)

if __name__ == '__main__':
    sum_reports()
