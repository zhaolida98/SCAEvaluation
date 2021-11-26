import csv
import json
import os

from src.cve_result_compare import get_intersect_component_and_cve


def batch_cve_repo(manifest_csv):
    csv_reader = csv.DictReader(manifest_csv)
    for row in csv_reader:
        scan_type = row['type']
        target_name = row['target']
        workding_dir = row['working_path']

        report_path = os.path.join(workding_dir, scan_type + '_report')
        tmp_json = get_intersect_component_and_cve(report_path)
        result_json_file = os.path.join(report_path, "cve_compare.json")
        with open(result_json_file, 'w') as f:
            json.dump(tmp_json, f)
    manifest_csv.close()


if __name__ == '__main__':
    manifest_csv_path = f"/home/nryet/testProjects/SCAEvaluation/manifest-test.csv"
    manifest_csv = open(manifest_csv_path, 'r')
    batch_cve_repo(manifest_csv)
