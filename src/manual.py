import csv

from src import batch_report_compare, batch_generate_mvn_gt, batch_tools_scan, report_folder_compare
import unittest

from src.batch_cve_repo import batch_cve_repo


class ManualOperations(unittest.TestCase):
    def setUp(self):
        self.manifest_csv_path = f"/home/nryet/testProjects/SCAEvaluation/manifest-test.csv"
        self.manifest_csv = open(self.manifest_csv_path, 'r')

        self.source_waiting_tools = ['scantist', 'whitesource', 'owasp', 'steady']
        self.unbuild_source_waiting_tools = ['scantist', 'owasp']
        self.jar_waiting_tools = ['whitesource', 'owasp', 'steady']

        self.comparator_list = ['scantist']
        # comparatee_list = ['scantist', 'whitesource', 'owasp']
        self.comparatee_list = ['qianxin']

    def test_batch_tools_scan(self):
        batch_tools_scan.batch_tools_scan(self.manifest_csv, self.source_waiting_tools,
                                          self.unbuild_source_waiting_tools, self.jar_waiting_tools)

    def test_generate_ground_truth(self):
        batch_generate_mvn_gt.batch_generate_mvn_gt(self.manifest_csv)

    def test_batch_report_compare(self):
        csv_reader = csv.DictReader(self.manifest_csv)
        for row in csv_reader:
            working_dir = row['working_path']
            batch_report_compare.generate_sca_tools_report(working_dir, self.comparator_list, self.comparatee_list)

    def test_single_folder_report_compare(self):
        working_dir = "/testsuit1/guava-23.0/unbuild_source_report"
        project_name = 'guava-23.0'
        report_folder_compare.generate_sca_tools_report(working_dir, project_name)

    def test_batch_cve_repo(self):
        batch_cve_repo(self.manifest_csv)



