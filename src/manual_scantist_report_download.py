import csv
import os
import requests
from util.ComponentReport import ComponentReport
from util.IssueReport import IssueReport

from util.utils import write_component_report, write_issue_report

testsuite = "testsuite2"


def download_comp_report(scan_id):
    url = f"https://api.scantist.io/v1/scans/{scan_id}/library-versions/export/?report_format=csv&language=en"
    print("query on", url)
    payload={}
    headers = {
    'Authorization': '5c7a40da-4c54-4a5b-b3d2-2170b7e4cd3f',
    'Content-Type': 'application/json'
    }

    response = requests.request("GET", url, headers=headers, data=payload)
    response = response.json()
    if 'download_link' in response:
        return response['download_link']
    else:
        return None


def download_vuln_report(scan_id):
    url = f"https://api.scantist.io/v1/scans/{scan_id}/issues/export/?report_format=csv&language=en"
    print("query on", url)
    payload={}
    headers = {
    'Authorization': '5c7a40da-4c54-4a5b-b3d2-2170b7e4cd3f',
    'Content-Type': 'application/json'
    }

    response = requests.request("GET", url, headers=headers, data=payload)
    response = response.json()
    if 'download_link' in response:
        return response['download_link']
    else:
        print("error in getting download link")
        return None

def save_cmp_report(link, output_path, repo_name):
    scantist_report = os.path.join(output_path, "scantist_report", f"{repo_name}-report")
    os.makedirs(scantist_report, exist_ok=True)
    origin_cmp_name = f"scan_nn_component.csv"
    name = f"scantist-component-{repo_name}"
    response = requests.request("GET", link)
    with open(os.path.join(scantist_report, origin_cmp_name), 'w') as f:
        f.write(response.text)
    
    component_report = open(os.path.join(scantist_report, origin_cmp_name), 'r')
    component_reader = csv.DictReader(component_report)
    matched_component_dict = {}
    for component in component_reader:
        match_status = component['Status']
        if match_status == "un-matched":
            continue
        scope = component['Scope']
        language = component['Language']
        if scope.lower() in ['test', 'system', 'provided']:
            continue
        if language.lower() not in ['java', '-']:
            continue
        if ' ' in component['Library']:
               artifact, group = component['Library'].split(' ')
               component['Library'] = f"{group}:{artifact}"
        tmp = ComponentReport(component['Library'], component['Library Version'])
        matched_component_dict[tmp.get_hash()] = tmp.info
    write_component_report(matched_component_dict.values(), name, output_path)
    

def save_issue_report(link, output_path, repo_name):
    scantist_report = os.path.join(output_path, "scantist_report", f"{repo_name}-report")
    os.makedirs(scantist_report, exist_ok=True)
    origin_issue_name = f"scan_nn_issue.csv"
    name = f"scantist-issue-{repo_name}"
    response = requests.request("GET", link)
    with open(os.path.join(scantist_report, origin_issue_name), 'w') as f:
        f.write(response.text)

    issue_report = open(os.path.join(scantist_report, origin_issue_name), 'r')
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
        if language.lower() not in ['java', '-']:
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


def batch_download_saas():
    manifest_csv_path = f"/root/SCAEvaluation/{testsuite}/manifest-{testsuite}.csv"
    manifest_csv = open(manifest_csv_path, 'r')
    csv_reader = csv.DictReader(manifest_csv)
    for row in csv_reader:
        working_dir = row['working_path']
        name = row['report_name']
        scan_id = row['scanid']
        type = row['type']
        if type != 'saas':
            continue
        report_folder_name = "saas_report"
        output_path = os.path.join(working_dir, report_folder_name)
        cmp_link = download_comp_report(scan_id)
        issue_link = download_vuln_report(scan_id)
        save_cmp_report(cmp_link, output_path, name)
        save_issue_report(issue_link, output_path, name)

def batch_download_source():
    manifest_csv_path = f"/root/SCAEvaluation/{testsuite}/manifest-testsuite2_scantist_manual.csv"
    manifest_csv = open(manifest_csv_path, 'r')
    csv_reader = csv.DictReader(manifest_csv)
    for row in csv_reader:
        working_dir = row['working_path']
        name = row['target']
        scan_id = row['scanid']
        type = row['type']
        report_folder_name = f"{type}_report"
        output_path = os.path.join(working_dir, report_folder_name)
        cmp_link = download_comp_report(scan_id)
        issue_link = download_vuln_report(scan_id)
        save_cmp_report(cmp_link, output_path, name)
        save_issue_report(issue_link, output_path, name)

def download_single(scan_id, output_path, report_name):
    cmp_link = download_comp_report(scan_id)
    issue_link = download_vuln_report(scan_id)
    save_cmp_report(cmp_link, output_path, report_name)
    save_issue_report(issue_link, output_path, report_name)

if __name__ == "__main__":
    # batch_download_source()
    # batch_download_saas()
    # download_single(35274,"/root/SCAEvaluation/{testsuite2}/apache@dubbo/source_type", "apache@dubbo")
