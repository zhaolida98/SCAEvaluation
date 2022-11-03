"""
get the issues for ground truth component files and place the intersection report for cve comparsion
"""

import csv
import os
from util.utils import pretty_log
from get_issues_of_intersect_components import get_issues_of_intersect_components
from generate_intersect_comp_csv import get_intersect_component_report

manifest_csv_path = f"/root/SCAEvaluation/testsuite2/manifest-testsuite2.csv"

def batch_generate_cve_compare_case(manifest_csv):
    csv_reader = csv.DictReader(manifest_csv)
    for row in csv_reader:
        scan_type = row['type']
        target_name = row['target']
        workding_dir = row['working_path']
        report_path = os.path.join(workding_dir, scan_type+'_report')
        intersect_report_path = os.path.join(workding_dir, "intersect_report")
        saas_intersect_report_path = os.path.join(workding_dir, "saas_intersect_report")
        pretty_log(f"\n*********************{target_name}*********************")

        # ---- build ----
        if scan_type == 'source':
            # 1. query issue ground truth for component ground truth
            full_component_csv_file = os.path.join(report_path, f"groundtruth-component-{target_name}.csv")
            # query_issue_gt_by_comp_report(full_component_csv_file, report_path)

            # 2. get intersect component report and place in intersect_report
            get_intersect_component_report(report_path, intersect_report_path)

            # 3. query issue ground truth for intersected components
            intersect_component_csv = os.path.join(intersect_report_path, f"groundtruth-component-{target_name}.csv") 

            # 4. extract the CVEs related to the intersected components for each tool
            get_issues_of_intersect_components(report_path, intersect_component_csv, intersect_report_path)

        # ---- saas ----
        if scan_type == 'saas':
            # 2. get intersect component report and place in intersect_report
            get_intersect_component_report(report_path, saas_intersect_report_path)

            # 3. query issue ground truth for intersected components
            saas_intersect_component_csv = os.path.join(saas_intersect_report_path, f"groundtruth-component-{target_name}.csv") 

            # 4. extract the CVEs related to the intersected components for each tool
            get_issues_of_intersect_components(report_path, saas_intersect_component_csv, saas_intersect_report_path)


if __name__ == '__main__':
    manifest_csv = open(manifest_csv_path, 'r')
    batch_generate_cve_compare_case(manifest_csv)
    manifest_csv.close()

