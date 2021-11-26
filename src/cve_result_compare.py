import json
import os

from util.ComponentReportReader import ComponentReportReader
from util.IssueReportReader import IssueReportReader
from util.utils import pretty_log


def get_intersect_component_and_cve(target_dir):
    possible_tool_list = ['scantist', 'whitesource', 'owasp', 'steady', 'qianxin']
    target_dir = target_dir.strip(os.pathsep)
    base_name = os.path.basename(os.path.dirname(target_dir))
    comp_set_list = []
    report_list = {}
    # find possible report of all tools, and load them
    for tool in possible_tool_list:
        possible_component_name = os.path.join(target_dir, f"{tool}-component-{base_name}.csv")
        possible_issue_name = os.path.join(target_dir, f"{tool}-issue-{base_name}.csv")
        if os.path.isfile(possible_issue_name) and os.path.isfile(possible_component_name):
            pretty_log(f"{tool} in {base_name} is ready to compare")
        else:
            pretty_log(f"{tool} in {base_name} is not ready to compare", "WARNING")
            continue
        tmp_component_dict = ComponentReportReader(possible_component_name).get_report_dict()
        tmp_issue_dict = IssueReportReader(possible_issue_name).get_report_dict()
        report_list[tool] = {"component": tmp_component_dict,
                             "issue": tmp_issue_dict}
        tmp_comp_set = set()
        for component in tmp_component_dict:
            tmp_comp_set.add(component['hash'])
        comp_set_list.append(tmp_comp_set)

    # get intersection of all tools component result
    intersect_set = None
    if len(comp_set_list) > 0:
        intersect_set = comp_set_list[0]
        for comp_set in comp_set_list:
            intersect_set = intersect_set.intersection(comp_set)

    # only remain the intersect component related CVEs.
    if intersect_set is None or len(intersect_set) == 0:
        pretty_log(f"no intersect component for {base_name}", "WARNING")
        exit(1)
    else:
        pretty_log(f"{len(intersect_set)} components for {base_name}")

    common_issue_dict = {}
    for tool_name, values in report_list.items():
        common_issue = []
        for issue in values['issue']:
            if issue['componentId'] in intersect_set:
                common_issue.append(issue)
        common_issue_dict[tool_name] = common_issue
    report_list['common'] = {"component": list(intersect_set),
                             "issue": common_issue_dict}
    return report_list

if __name__ == '__main__':
    with open("result.json", 'w') as rs:
        json.dump(get_intersect_component_and_cve("/home/nryet/testProjects/SCAEvaluation/testsuit1/mall/source_report"), rs)


