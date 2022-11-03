import csv
import os
import json
from query_issue_gt_by_comp_report import get_issue_list

from util.ComponentReportReader import ComponentReportReader
from util.IssueReportReader import IssueReportReader
from util.utils import pretty_log
from util.utils import write_component_report


def single_get_cve_union(target_dir):
    """
    return structure:
    {
        gav: set(),
        gav2:set()
    }
    """
    possible_tool_list = ['whitesource', 'owasp', 'steady']
    target_dir = target_dir.strip(os.pathsep)
    base_name = os.path.basename(os.path.dirname(target_dir))
    cve_union = {}
    # find possible report of all tools, and load them
    pretty_log(f"****{base_name}****")
    for tool in possible_tool_list:
        possible_issue_name = os.path.join(target_dir, f"{tool}-issue-{base_name}.csv")
        if os.path.isfile(possible_issue_name):
            pretty_log(f"{tool}: \t\tready")
        else:
            pretty_log(f"{tool}: \t\tfailed")
            continue
        tmp_issue_dict = IssueReportReader(possible_issue_name).get_report_dict()
        for issue_item in tmp_issue_dict:
            if issue_item['componentId'] not in cve_union:
                cve_union[issue_item['componentId']] = {}
            if issue_item['publicId'] not in cve_union[issue_item['componentId']]:
                cve_union[issue_item['componentId']][issue_item['publicId']] = 0
            cve_union[issue_item['componentId']][issue_item['publicId']] += 1
    final_cve_union = {}
    for component in cve_union:
        tmp = set()
        for publicid in cve_union[component]:
            if cve_union[component][publicid] > 1:
                tmp.add(publicid)
        if len(tmp) > 0:
            final_cve_union[component] = tmp
    return final_cve_union

def batch_get_cve_union(manifest_csv):
    """
    cve_total_union structure
    {
        gav: {
            union_cve: set(),
            gt_cve: set(),
            fn_cve: set(),
            fp_cve: set(),
            diff_cnt: int
        }
    }
    """
    csv_reader = csv.DictReader(manifest_csv)
    cve_total_union = {}
    unique_cve_set = set()
    fp_cve_set = set()
    fn_cve_set = set()
    total_diff_cnt = 0
    for row in csv_reader:
        scan_type = row['type']
        workding_dir = row['working_path']
        target = row['target']
        report_path = os.path.join(workding_dir, scan_type+'_report')
        single_cve_union = single_get_cve_union(report_path)
        for gav, cve_set in single_cve_union.items():
            if '[' in gav:
                pretty_log(gav)
                exit(1)
            if gav not in cve_total_union:
                cve_total_union[gav] = {}
                cve_total_union[gav]["union_cve"] = set()
            cve_total_union[gav]['union_cve'] = cve_total_union[gav]['union_cve'].union(cve_set)
    pop_gav = []
    for gav in cve_total_union.keys():
        pretty_log(f"processing on {gav}")
        g,a,v = gav.split(':')
        gt_issue_set = set(get_issue_list(g, a, v))
        existing_cve = cve_total_union[gav]["union_cve"]
        cve_total_union[gav]["union_cve"] = list(existing_cve) 
        cve_total_union[gav]["gt_cve"] = list(gt_issue_set)
        cve_total_union[gav]["fn_cve"] = list(gt_issue_set.difference(existing_cve))
        cve_total_union[gav]["fp_cve"] = list(existing_cve.difference(gt_issue_set))
        cve_total_union[gav]["diff_cnt"] = len(cve_total_union[gav]["fn_cve"]) + len(cve_total_union[gav]["fp_cve"])
        total_diff_cnt += cve_total_union[gav]["diff_cnt"]
        fn_cve_set = fn_cve_set.union(gt_issue_set.difference(existing_cve))
        fp_cve_set = fp_cve_set.union(existing_cve.difference(gt_issue_set))
        if cve_total_union[gav]["diff_cnt"] == 0:
            pop_gav.append(gav)
    for gav in pop_gav:
        cve_total_union.pop(gav)
    
    final_dict = {
        "total_diff": total_diff_cnt,
        "unique_cve": len(fn_cve_set.union(fp_cve_set)),
        "fn_cve_set": list(fn_cve_set),
        "fp_cve_set": list(fp_cve_set),
        "detail": cve_total_union
    }

    with open('cve_total_union.json', 'w') as f:
        json.dump(final_dict, f)


if __name__ == "__main__":
    manifest_csv_path = f"/root/SCAEvaluation/testsuite1/manifest-testsuite1.csv"
    manifest_csv = open(manifest_csv_path, 'r')
    batch_get_cve_union(manifest_csv)