import os
import csv
from util.utils import write_issue_report
from util.IssueReport import IssueReport
repo_name = "tutorials"
issue_report = open(f"/root/SCAEvaluation/testsuite2/SCAEvaluation-SAAS-Test@{repo_name}/source_report/scantist_report/SCAEvaluation-SAAS-Test@{repo_name}-report/scan-40921-vulnerability.csv", 'r')
name = f"scantist-issue-SCAEvaluation-SAAS-Test@{repo_name}"
output_path = f"/root/SCAEvaluation/testsuite2/SCAEvaluation-SAAS-Test@{repo_name}/source_report"
issue_reader = csv.DictReader(issue_report)
matched_issue_dict = {}
for issue in issue_reader:
    match_status = issue['Status']
    if match_status == "un-matched":
        continue
    scope = issue['Scope']
    language = issue['Language']
    if scope.lower() in ['test', 'system', 'provided']:
        continue
    if language.lower() not in ['java']:
        continue
    lib_name = issue['Library'].strip()
    if ' ' not in lib_name:
        lib_name = f"{lib_name} {lib_name}"
    library_name = issue['Library']
    library_version = issue['Library Version']
    public_id = issue['Public ID']
    tmp = IssueReport(library_name, library_version, public_id)
    matched_issue_dict[tmp.get_hash()] = tmp.info
write_issue_report(matched_issue_dict.values(), name, output_path)