import json
import os

from util.ComponentReportReader import ComponentReportReader
from util.IssueReportReader import IssueReportReader
from util.utils import pretty_log
from util.utils import write_component_report



def get_intersect_component_report(target_dir, output_dir):
    possible_tool_list = ['whitesource', 'owasp', 'steady', 'ossindex', 'snyk', 'groundtruth', 'dependabot', 'scantist']
    target_dir = target_dir.strip(os.pathsep)
    base_name = os.path.basename(os.path.dirname(target_dir))
    comp_set_list = []
    report_list = {}
    # find possible report of all tools, and load them
    for tool in possible_tool_list:
        possible_component_name = os.path.join(target_dir, f"{tool}-component-{base_name}.csv")
        possible_issue_name = os.path.join(target_dir, f"{tool}-issue-{base_name}.csv")
        if os.path.isfile(possible_issue_name) and os.path.isfile(possible_component_name):
            pretty_log(f"{tool}: \t\tready")
        else:
            pretty_log(f"{tool}: \t\tfailed")
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
    else:
        pretty_log(f"{len(intersect_set)} common components for {base_name}")

    # write intersect component to file
    intersect_comp_dict_list = []
    for component_item in intersect_set:
        g, a, v = component_item.split(":")
        intersect_comp_dict_list.append({
            "Library": f"{g}:{a}",
            "Library Version": v,
        })
    write_component_report(intersect_comp_dict_list, f"groundtruth-component-{base_name}", output_dir)
    return report_list


if __name__ == '__main__':
    # get the intersection of all components and write to a file into intersect_report
    # input: source_report folder
    # output: write a ground truth component into intersect folder
    target_report_dir = "/root/SCAEvaluation/testsuite2/SCAEvaluation-SAAS-Test@mall/saas_report"
    intersection_dir = target_report_dir.replace("saas_report", "saas_intersect_report")

    get_intersect_component_report(target_report_dir, intersection_dir)


