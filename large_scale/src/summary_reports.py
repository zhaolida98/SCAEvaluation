import csv
import os
import shutil

import json
from threading import local
from util.utils import pretty_log, exec_command

report_status_path = "/root/SCAEvaluation/large_scale/reports/report_status.json"
report_path = "/root/SCAEvaluation/large_scale/reports"
summary_path = "/root/SCAEvaluation/large_scale/src/report_summary.json"

def sum_reports(report_path):
    total_related_cmp_cnt = 0
    total_unrelated_cmp_cnt = 0
    total_shaded_cmp_cnt = 0
    total_related_cve_cnt = 0
    total_unrelated_cve_cnt = 0
    total_shaded_cve_cnt = 0
    scope_test_cmp_cnt = 0
    scope_test_cve_cnt = 0
    scope_provided_cmp_cnt = 0
    scope_provided_cve_cnt = 0
    type_pom_cmp_cnt = 0
    type_pom_cve_cnt = 0
    type_test_jar_cmp_cnt = 0
    type_test_jar_cve_cnt = 0
    classifier_tests_cmp_cnt = 0
    classifier_tests_cve_cnt = 0
    snapshot_cmp_cnt = 0
    snapshot_cve_cnt = 0
    scope_system_cmp_cnt = 0
    scope_system_cve_cnt = 0
    for repo_name in os.listdir(report_path):
        if repo_name == "report_status.json":
            continue
        path = os.path.join(report_path, repo_name)
        with open(path, 'r') as f:
            content = json.loads(f.read())
            if "summary" in content:
                total_related_cmp_cnt += content['summary']['related_cmp_cnt']
                total_unrelated_cmp_cnt += content['summary']['unrelated_cmp_cnt']
                total_shaded_cmp_cnt += content['summary']['shaded_cmp_cnt']
                total_related_cve_cnt += content['summary']['related_cve_cnt']
                total_unrelated_cve_cnt += content['summary']['unrelated_cve_cnt']
                total_shaded_cve_cnt += content['summary']['shaded_cve_cnt']
            for item in content['unrelated']:
                info = content['unrelated'][item]
                if info['type'] == 'pom':
                    type_pom_cmp_cnt += 1
                    type_pom_cve_cnt += len(info['cve_list'])
                if info['type'] == 'test-jar':
                    type_test_jar_cmp_cnt += 1
                    type_test_jar_cve_cnt += len(info['cve_list'])
                if info['classifier'] == 'tests':
                    classifier_tests_cmp_cnt += 1
                    classifier_tests_cve_cnt += len(info['cve_list'])
                if info['scope'] == 'test':
                    scope_test_cmp_cnt += 1
                    scope_test_cve_cnt += len(info['cve_list'])
                if info['scope'] == 'provided':
                    scope_provided_cmp_cnt += 1
                    scope_provided_cve_cnt += len(info['cve_list'])
                if info['scope'] == 'system':
                    scope_system_cmp_cnt += 1
                    scope_system_cve_cnt += len(info['cve_list'])
                if 'SNAPSHOT' in info['gav']:
                    snapshot_cmp_cnt += 1
                    snapshot_cve_cnt += len(info['cve_list'])

    total_cmp_fp_reduce = total_unrelated_cmp_cnt / (total_unrelated_cmp_cnt + total_related_cmp_cnt)
    total_cmp_fn_reduce = total_shaded_cmp_cnt / (total_unrelated_cmp_cnt + total_related_cmp_cnt)
    total_cve_fp_reduce = total_unrelated_cve_cnt / (total_unrelated_cve_cnt + total_related_cve_cnt)
    total_cve_fn_reduce = total_shaded_cve_cnt / (total_unrelated_cmp_cnt + total_related_cve_cnt)

    summary_json = {
        "total_related_cmp_cnt": total_related_cmp_cnt,
        "total_unrelated_cmp_cnt": total_unrelated_cmp_cnt,
        "total_shaded_cmp_cnt": total_shaded_cmp_cnt,
        "total_related_cve_cnt": total_related_cve_cnt,
        "total_unrelated_cve_cnt": total_unrelated_cve_cnt,
        "total_shaded_cve_cnt": total_shaded_cve_cnt,
        "total_cmp_fp_reduce ": total_cmp_fp_reduce, 
        "total_cmp_fn_reduce": total_cmp_fn_reduce, 
        "total_cve_fp_reduce": total_cve_fp_reduce, 
        "total_cve_fn_reduce": total_cve_fn_reduce,
        "scope_test_cmp_cnt": scope_test_cmp_cnt,
        "scope_test_cve_cnt": scope_test_cve_cnt,
        "scope_provided_cmp_cnt": scope_provided_cmp_cnt,
        "scope_provided_cve_cnt": scope_provided_cve_cnt,
        "scope_system_cmp_cnt": scope_system_cmp_cnt,
        "scope_system_cve_cnt": scope_system_cve_cnt,
        "type_pom_cmp_cnt": type_pom_cmp_cnt,
        "type_pom_cve_cnt": type_pom_cve_cnt,
        "type_test_jar_cmp_cnt": type_test_jar_cmp_cnt,
        "type_test_jar_cve_cnt": type_test_jar_cve_cnt,
        "classifier_tests_cmp_cnt": classifier_tests_cmp_cnt,
        "classifier_tests_cve_cnt": classifier_tests_cve_cnt,
        "snapshot_cmp_cnt": snapshot_cmp_cnt,
        "snapshot_cve_cnt": snapshot_cve_cnt,
    }

    with open(summary_path, 'w') as f:
        json.dump(summary_json, f)
        pretty_log("process finished, saving report summary json")


if __name__ == '__main__':
    sum_reports(report_path)
