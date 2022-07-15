import os
from util.utils import write_issue_report

from util.ComponentReportReader import ComponentReportReader
from util.IssueReportReader import IssueReportReader
from util.utils import pretty_log


def get_issues_of_intersect_components(source_report_folder, intersection_component_csv, output_dir):
    possible_tool_list = ['groundtruth', 'whitesource', 'owasp', 'steady', 'ossindex', 'snyk', 'dependabot', 'scantist']
    source_report_folder = source_report_folder.strip(os.pathsep)
    base_name = os.path.basename(os.path.dirname(source_report_folder))
    intersect_comp_dict_list = ComponentReportReader(intersection_component_csv).get_report_dict()
    intersect_comp_gav_list = set([comp_item['hash'] for comp_item in intersect_comp_dict_list])
    # find possible report of all tools, and load them
    for tool in possible_tool_list:
        intersection_comp_related_issue = []
        possible_issue_path = os.path.join(source_report_folder, f"{tool}-issue-{base_name}.csv")
        if not os.path.isfile(possible_issue_path):
            continue
        tmp_issue_dict_list = IssueReportReader(possible_issue_path).get_report_dict()
        for issue_item in tmp_issue_dict_list:
            if issue_item['componentId'] in intersect_comp_gav_list:
                g, a, v = issue_item['componentId'].split(':')
                tmp_issue = {
                    "Library": f"{g}:{a}", 
                    "Library Version": v,
                    "Public ID": issue_item['publicId']
                }
                intersection_comp_related_issue.append(tmp_issue)
        write_issue_report(intersection_comp_related_issue, f"{tool}-issue-{base_name}", output_dir)


if __name__ == '__main__':
    # use intersected component report as reference, only select the issues related to those component
    # input: target source_report dir, intersection_component_report
    # output: all tools issue report that only contains intersected components
    source_report_folder = "/root/SCAEvaluation/testsuite2/SCAEvaluation-SAAS-Test@mall/saas_report"
    intersection_component_csv = "/root/SCAEvaluation/testsuite2/SCAEvaluation-SAAS-Test@mall/saas_intersect_report/groundtruth-component-SCAEvaluation-SAAS-Test@mall.csv"
    intersection_dir = os.path.dirname(intersection_component_csv)
    get_issues_of_intersect_components(source_report_folder, intersection_component_csv, intersection_dir)