import os
import requests
import csv


def pretty_log(log, logtype="INFO"):
    print(f'[{logtype}] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}| {log}')


def write_issue_report(issue_dict_list, report_name, output_dir):
    field_names = issue_field_names
    try:
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        with open(f"{output_dir}/{report_name}.csv", mode="w", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=field_names)
            writer.writeheader()
            writer.writerows(issue_dict_list)
    except:
        raise IOError(f"write issue report for {report_name} failed.")
    pretty_log(f"write result to {output_dir}/{report_name}.csv")
    return os.path.join(output_dir, report_name)


def get_issue_list(group_id, artifact_id, version):
    url = 'http://94.74.83.184:8086/issues'
    payload = f"""
        {{
            "name": "{artifact_id}",
            "vendor": "{group_id}",
            "version": "{version}",
            "platform": "maven"
        }}
    """
    header = {"Content-Type": "application/json", "charset": "UTF-8"}
    res = requests.post(url, headers=header, data=payload)
    # print(res.json())
    issue_list = []
    if res.status_code != 200:
        pretty_log(f" CVE list querying failed: {group_id}:{artifact_id}:{version}")
        return []
    else:
        content = res.json()
        if len(content) == 0:
            # print(f"{group_id}:{artifact_id}:{version} query cve is empty")
            return []
        for item in content:
            if item['libraryVersion']['libraryName'] != artifact_id or item['libraryVersion']['libraryVendor'] != group_id:
                continue
            if item['issue'].startswith('CVE') or item['issue'].startswith('CNVD'):
                issue_list.append(item['issue'])
    return issue_list

def query_issue_gt_by_comp_report(component_csv_file:str, issue_report_outdir:str):
    pretty_log(f"processing on {component_csv_file}")
    assert os.path.isfile(component_csv_file)
    component_csv = open(component_csv_file, 'r')
    component_csv_reader = csv.DictReader(component_csv)
    cve_list = []
    for component in component_csv_reader:
        ga_pair = component['Library'].split(':')
        if len(ga_pair) == 2:
            artifact_id = ga_pair[1].strip()
            group_id = ga_pair[0].strip()
            version = component['Library Version']
            comp_cve_list = get_issue_list(group_id, artifact_id, version)
            for cve in comp_cve_list:
                issue_item = {
                    "Library": f"{group_id}:{artifact_id}",
                    "Library Version": version,
                    "Public ID": cve
                }
                
                cve_list.append(issue_item)
        else:
            pretty_log(f"not standard maven GAV, skip cve query: {ga_pair}")
    issue_report_base_name = os.path.basename(component_csv_file).replace("component", "issue").replace(".csv", "")
    write_issue_report(cve_list, issue_report_base_name, issue_report_outdir)
    component_csv.close()
    pretty_log(f'write issue report to {os.path.join(issue_report_outdir, issue_report_base_name)}')
    return os.path.join(issue_report_outdir, issue_report_base_name)

if __name__ == "__main__":
    # query the groundtruth issues for a component report
    # input component report path
    # issue report output folder, name will always be ground truth-issue-XXX.csv
    issue_report_outdir = "/root/SCAEvaluation/testsuite1/macrozheng@mall/source_report"
    component_csv_file = "/root/SCAEvaluation/testsuite1/macrozheng@mall/source_report/groundtruth-component-macrozheng@mall.csv"
    query_issue_gt_by_comp_report(component_csv_file, issue_report_outdir)
    # print(get_issue_list("org.apache.httpcomponents", "httpclient", "4.5.12"))