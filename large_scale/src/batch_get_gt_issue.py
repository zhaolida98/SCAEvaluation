# search the CVE for all deps in report_xxx.json and make summary
# also, generate issue csv
from asyncore import write
import csv
import os
import shutil
import json
from util.ComponentReport import ComponentReport
from util.IssueReport import IssueReport
from util.issueUtils import get_issue_list_with_cache
from util.utils import pretty_log, write_component_report, write_issue_report

report_path = "/home/lida/SCAEvaluation-main/large_scale/reports"
manifest_path = '/home/lida/SCAEvaluation-main/large_scale/manifest/build_manifest.csv'
summary_path = "/home/lida/SCAEvaluation-main/large_scale/manifest/report_summary.json"
cve_cache_path = '/home/lida/SCAEvaluation-main/large_scale/cache/cve_cache.json'
verified_cve = '/home/lida/SCAEvaluation-main/large_scale/cache/verified_cve.json'

def sum_reports():
    name_list = []
    with open(manifest_path, 'r') as f:
        csvreader = csv.DictReader(f)
        name_list = [i['target'] for i in csvreader]
    for idx, repo_name in enumerate(name_list):
        print(f"processing on {repo_name}: {idx}")
        gt_path = os.path.join(report_path, repo_name,'groundtruth', f'report_{repo_name}.json')
        # gt_verified_issue_path = os.path.join(report_path, repo_name,'groundtruth', f'report_{repo_name}_verified.json')
        if not os.path.isfile(gt_path):
            continue
        content = {}
        with open(gt_path, 'r') as f:
            content = json.load(f)
        
        get_cve_list(content)
        make_summary(content)
        component_json2csv(content, repo_name)
        issue_json2csv(content, repo_name)
        # with open(gt_verified_issue_path, 'w') as f:
            # json.dump(content, f)
        with open(gt_path, 'w') as f:
            json.dump(content, f)


def issue_json2csv(content, repo_name):
    issue_list = []
    related = content['related']
    shaded = content['shaded']
    for i in related.keys():
        gav = i.split(':')
        if len(gav)!= 3:
            continue
        g, a, v = gav[0], gav[1], gav[2]
        for cve in related[i]['cve_list']:
            issue = IssueReport(f'{g}:{a}',v, cve)
            issue_list.append(issue.info)
    for i in shaded.keys():
        gav = i.split(':')
        if len(gav)!= 3:
            continue
        g, a, v = gav[0], gav[1], gav[2]
        for cve in shaded[i]['cve_list']:
            issue = IssueReport(f'{g}:{a}',v, cve)
            issue_list.append(issue.info)
    gt_csv_path = os.path.join(report_path, repo_name,'groundtruth')
    write_issue_report(issue_list, f'groundtruth-issue-{repo_name}', gt_csv_path)


def component_json2csv(content, repo_name):
    comp_list = []
    related = content['related']
    shaded = content['shaded']
    for i in related.keys():
        gav = i.split(':')
        if len(gav)!= 3:
            continue
        g, a, v = gav[0], gav[1], gav[2]
        comp = ComponentReport(f'{g}:{a}',v)
        comp_list.append(comp.info)
    for i in shaded.keys():
        gav = i.split(':')
        if len(gav)!= 3:
            continue
        g, a, v = gav[0], gav[1], gav[2]
        comp = ComponentReport(f'{g}:{a}',v)
        comp_list.append(comp.info)
    gt_csv_path = os.path.join(report_path, repo_name,'groundtruth')
    write_component_report(comp_list, f'groundtruth-component-{repo_name}', gt_csv_path)
        

def get_cve_list(dep_dict: dict, write_back = False):
    cve_cache_json = {}
    if os.path.isfile(cve_cache_path):
        with open(cve_cache_path, 'r') as f:
            cve_cache_json = json.load(f)
    try: 
        for related_dep in dep_dict["related"]:
            cve_list = get_issue_list_with_cache(related_dep, cve_cache_json)
            # cve_list = keep_verified_only(verified_cve_set, cve_list)
            dep_dict['related'][related_dep]['cve_list'] = cve_list
        for unrelated_dep in dep_dict["unrelated"]:
            cve_list = get_issue_list_with_cache(unrelated_dep, cve_cache_json)
            # cve_list = keep_verified_only(verified_cve_set, cve_list)
            dep_dict['unrelated'][unrelated_dep]['cve_list'] = cve_list
        for shaded_dep in dep_dict["shaded"]:
            cve_list = get_issue_list_with_cache(shaded_dep, cve_cache_json)
            # cve_list = keep_verified_only(verified_cve_set, cve_list)
            dep_dict['shaded'][shaded_dep]['cve_list'] = cve_list
    except Exception as e:
        pretty_log("get_cve_list | error", e)
        pass
    finally:
        if write_back:
            with open(cve_cache_path, 'w') as f:
                json.dump(cve_cache_json, f)
                pretty_log("process finished, saving the cve to cache")
    return dep_dict


def keep_verified_only(verify_set, cve_list):
    verified_cve_list = []
    for cve in cve_list:
        if cve in verify_set:
            verified_cve_list.append(cve)
    return verified_cve_list


def make_summary(dep_dict: dict):
    related_cve_cnt = 0
    unrelated_cve_cnt = 0
    shaded_cve_cnt = 0
    for related_dep in dep_dict["related"]:
        related_cve_cnt += len(dep_dict["related"][related_dep]["cve_list"])
    for unrelated_dep in dep_dict["unrelated"]:
        unrelated_cve_cnt += len(dep_dict["unrelated"][unrelated_dep]["cve_list"])
    for shaded_dep in dep_dict["shaded"]:
        shaded_cve_cnt += len(dep_dict["shaded"][shaded_dep]["cve_list"])

    dep_dict["summary"] = {
        "related_cmp_cnt": len(dep_dict['related']),
        "unrelated_cmp_cnt": len(dep_dict['unrelated']),
        "shaded_cmp_cnt": len(dep_dict['shaded']),
        "related_cve_cnt": related_cve_cnt,
        "unrelated_cve_cnt": unrelated_cve_cnt,
        "shaded_cve_cnt": shaded_cve_cnt,
    }
    return dep_dict


if __name__ == '__main__':
    sum_reports()
