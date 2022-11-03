# parse snyk results dependencies.json and issues.json into csvs and spread them into the folders
import json, csv, os
from util.utils import write_component_report, write_issue_report

from util.ComponentReport import ComponentReport
from util.IssueReport import IssueReport


report_path = '/home/lida/SCAEvaluation-main/large_scale/reports'
dependency_json = '/home/lida/SCAEvaluation-main/large_scale/cache/dependencies.json'
issue_json = '/home/lida/SCAEvaluation-main/large_scale/cache/issues.json'

def parse_snyk_dependencies(dependency_json):
    with open(dependency_json, 'r') as f:
        json_reader = json.load(f)
        for k, v in json_reader.items():
            print('processing', k)
            project_folder_name = k.replace('/', '@')
            project_report_path = os.path.join(report_path, project_folder_name, 'prebuild')
            if not os.path.isdir(project_report_path):
                os.makedirs(project_report_path, exist_ok=True)
            dependency_repo_name = f'snyk-component-{project_folder_name}'
            component_list = []
            for deps in v['data']:
                name_split = deps.split('@')
                component = ComponentReport(name_split[0], name_split[1])
                component_list.append(component.info)
            write_component_report(component_list, dependency_repo_name, project_report_path)


def parse_snyk_issues(issue_json):
    with open(issue_json, 'r') as f:
        json_reader = json.load(f)
        for k, v in json_reader.items():
            print('processing', k)
            project_folder_name = k.replace('/', '@')
            project_report_path = os.path.join(report_path, project_folder_name, 'prebuild')
            if not os.path.isdir(project_report_path):
                os.makedirs(project_report_path, exist_ok=True)
            issue_repo_name = f'snyk-issue-{project_folder_name}'
            issue_list = []
            for deps in v['data']:
                name_split = deps.split('@')
                issue = IssueReport(name_split[1], name_split[2], name_split[0])
                issue_list.append(issue.info)
            write_issue_report(issue_list, issue_repo_name, project_report_path)


def generate_snyk_status(dependency_json):
    item_list = []
    with open(dependency_json, 'r') as f:
        json_reader = json.load(f)
        for k, v in json_reader.items():
            print('processing', k)
            project_folder_name = k.replace('/', '@')
            if len(v['data']) != 0:
                tmp = {
                    "Library": project_folder_name,
                    "target": "snyk",
                    "status": "success",
                    "time": 0,
                    "log": ""
                }
                item_list.append(tmp)
    with open("/home/lida/SCAEvaluation-main/large_scale/manifest/snyk_status.csv", 'w') as f:
        writer = csv.DictWriter(f, fieldnames=['Library', 'target', 'status', 'time', 'log'])
        writer.writerows(item_list)

# parse_snyk_dependencies(dependency_json)
# parse_snyk_issues(issue_json)
generate_snyk_status(dependency_json)

