import json
import os
import pathlib
import time
import csv
import shutil



def compare_components(sca_component_report_path, groundtruth_component_report_path):
    # return:
    # sca_component_report summary, groundtruth_component_report,
    # TPL FP, TPL FN
    # TPLV FP, TPLV FN
    sca_components = get_component_report_detail(sca_component_report_path)
    groundtruth_components = get_component_report_detail(groundtruth_component_report_path)
    tpl_tp = set(sca_components["libraries"]["details"]).intersection(
        set(groundtruth_components["libraries"]["details"])
    )
    tplv_tp = set(sca_components["libraryversions"]["details"]).intersection(
        set(groundtruth_components["libraryversions"]["details"])
    )
    tpl_fn = set(groundtruth_components["libraries"]["details"]).difference(
        set(sca_components["libraries"]["details"])
    )
    tplv_fn = set(groundtruth_components["libraryversions"]["details"]).difference(
        set(sca_components["libraryversions"]["details"])
    )
    tpl_fp = set(sca_components["libraries"]["details"]).difference(
        set(groundtruth_components["libraries"]["details"])
    )
    tplv_fp = set(sca_components["libraryversions"]["details"]).difference(
        set(groundtruth_components["libraryversions"]["details"])
    )
    P_TPL = len(tpl_tp) / sca_components["libraries"]["unique_count"] \
        if sca_components["libraries"]["unique_count"] != 0 else -1
    R_TPL = len(tpl_tp) / groundtruth_components["libraries"]["unique_count"] \
        if groundtruth_components["libraries"]["unique_count"] != 0 else -1
    P_TPLV = len(tplv_tp) / sca_components["libraryversions"]["unique_count"] \
        if sca_components["libraryversions"]["unique_count"] != 0 else -1
    R_TPLV = len(tplv_tp) / groundtruth_components["libraryversions"]["unique_count"] \
        if groundtruth_components["libraryversions"]["unique_count"] != 0 else -1
    return {
        "sca_components": sca_components,
        "groundtruth_components": groundtruth_components,
        "tpl_tp": list(tpl_tp),
        "tplv_tp": list(tplv_tp),
        "tpl_fn": list(tpl_fn),
        "tplv_fn": list(tplv_fn),
        "tpl_fp": list(tpl_fp),
        "tplv_fp": list(tplv_fp),
        "tpl_tp_cnt": len(list(tpl_tp)),
        "tplv_tp_cnt": len(list(tplv_tp)),
        "tpl_fn_cnt": len(list(tpl_fn)),
        "tplv_fn_cnt": len(list(tplv_fn)),
        "tpl_fp_cnt": len(list(tpl_fp)),
        "tplv_fp_cnt": len(list(tplv_fp)),
        "P_TPL": P_TPL,
        "R_TPL": R_TPL,
        "P_TPLV": P_TPLV,
        "R_TPLV": R_TPLV,
    }


def get_component_report_detail(component_report_path):
    libraries = []
    libraryversions = []
    with open(component_report_path, mode="r", encoding="UTF-8") as csv_file:
        csv_reader = csv.DictReader(csv_file)
        line_count = 0
        for row in csv_reader:
            line_count += 1
            if line_count == 0:
                pretty_log(f'{component_report_path} Column names are {", ".join(row)}', 'DEBUG')
            raw_library = row["Library"].replace("None", "").strip().strip('-')

            if " " in raw_library:
                raw_lib, raw_org = raw_library.replace(": ", ":").split(" ")
                raw_lib = raw_lib.strip('-')
                raw_library = f"{raw_org}:{raw_lib}"
            libraries.append(raw_library)
            if "Version" in row:
                libraryversions.append("#".join([raw_library, row["Version"]]))
            else:
                libraryversions.append("#".join([raw_library, row["Library Version"]]))

    result = {
        "libraries": {"count": len(libraries), "details": libraries, "unique_count": len(set(libraries))},
        "libraryversions": {"count": len(libraryversions), "details": libraryversions, "unique_count": len(set(libraryversions))},
    }
    pretty_log(f"finished processing {component_report_path}, {line_count} lines, find {len(libraries)} libraries, {len(libraryversions)} library versions")
    # pretty_log(f"{component_report_path} result: {result}")
    return result


def get_issue_report_detail(issue_report_path):
    cve_list = []
    libraryversion_list = []
    with open(issue_report_path, mode="r") as csv_file:
        csv_reader = csv.DictReader(csv_file)
        line_count = 0
        for row in csv_reader:
            line_count += 1
            if line_count == 0:
                pretty_log(f'Column names are {", ".join(row)}')
            cve_list.append(row["Public ID"])
            libraryversion_list.append("#".join([row["Library"], row["Library Version"], row["Public ID"]]))
    result = {
        "cve": {"details": cve_list, "count": len(cve_list)},
        "library_versions": {"details": list(set(libraryversion_list)), "count": len(set(libraryversion_list))}
    }
    pretty_log(f"finished processing {issue_report_path}, {line_count} lines, find {len(cve_list)} cves")
    # pretty_log(f"{issue_report_path} result: {result}")
    return result


def compare_issues(sca_issue_report_path, groundtruth_issue_report_path):
    sca_issue = get_issue_report_detail(sca_issue_report_path)
    groundtruth_issue = get_issue_report_detail(groundtruth_issue_report_path)
    unique_cve_tp = set(sca_issue["cve"]["details"]).intersection(
        set(groundtruth_issue["cve"]["details"])
    )
    unique_cve_fn = set(groundtruth_issue["cve"]["details"]).difference(
        set(sca_issue["cve"]["details"])
    )
    unique_cve_fp = set(sca_issue["cve"]["details"]).difference(
        set(groundtruth_issue["cve"]["details"])
    )
    gav_cve_tp = set(sca_issue["library_versions"]["details"]).intersection(
        set(groundtruth_issue["library_versions"]["details"])
    )
    gav_cve_fn = set(groundtruth_issue["library_versions"]["details"]).difference(
        set(sca_issue["library_versions"]["details"])
    )
    gav_cve_fp = set(sca_issue["library_versions"]["details"]).difference(
        set(groundtruth_issue["library_versions"]["details"])
    )
    P_U_CVE = len(unique_cve_tp) / sca_issue["cve"]["count"] \
        if sca_issue["cve"]["count"] != 0 else -1
    R_U_CVE = len(unique_cve_tp) / groundtruth_issue["cve"]["count"] \
        if groundtruth_issue["cve"]["count"] != 0 else -1
    
    P_GAV_CVE = len(gav_cve_tp) / sca_issue["library_versions"]["count"] \
        if sca_issue["library_versions"]["count"] != 0 else -1
    R_GAV_CVE = len(gav_cve_tp) / groundtruth_issue["library_versions"]["count"] \
        if groundtruth_issue["library_versions"]["count"] != 0 else -1
    
    return {
        "sca_issues": sca_issue,
        "groundtruth_issues": groundtruth_issue,
        "unique_cve_tp": list(unique_cve_tp),
        "unique_cve_fn": list(unique_cve_fn),
        "unique_cve_fp": list(unique_cve_fp),
        "gav_cve_tp": list(gav_cve_tp),
        "gav_cve_fn": list(gav_cve_fn),
        "gav_cve_fp": list(gav_cve_fp),
        "unique_cve_tp_cnt": len(list(unique_cve_tp)),
        "unique_cve_fn_cnt": len(list(unique_cve_fn)),
        "unique_cve_fp_cnt": len(list(unique_cve_fp)),
        "gav_cve_tp_cnt": len(list(gav_cve_tp)),
        "gav_cve_fn_cnt": len(list(gav_cve_fn)),
        "gav_cve_fp_cnt": len(list(gav_cve_fp)),
        "R_U_CVE": R_U_CVE,
        "P_U_CVE": P_U_CVE,
        "R_GAV_CVE": R_GAV_CVE,
        "P_GAV_CVE": P_GAV_CVE,
    }


def pretty_log(log, logtype="INFO"):
    print(f'[{logtype}] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}| {log}')


def generate_sca_tools_report(working_dir: str, report_folder_name, comparator_list, comparatee_list, test_case=''):
    for comparator in comparator_list:
        for comparatee in comparatee_list:
            # skip self compare
            if comparator == comparatee:
                continue
            current_report = {
                "comparator": comparator,
                "comparatee": comparatee,
                "report_per_case": [],
            }

            case_report = {
                "testcase": "",
                "component_report": {},
                "issue_report": {},
            }
            if not test_case:
                test_case = os.path.basename(working_dir)
            case_report["testcase"] = test_case
            comparator_component_report = os.path.join(working_dir, report_folder_name, f"{comparator}-component-{test_case}.csv")
            comparator_issue_report = os.path.join(working_dir, report_folder_name, f"{comparator}-issue-{test_case}.csv")
            comparatee_component_report = os.path.join(working_dir, report_folder_name, f"{comparatee}-component-{test_case}.csv")
            comparatee_issue_report = os.path.join(working_dir, report_folder_name, f"{comparatee}-issue-{test_case}.csv")
            if os.path.isfile(comparatee_component_report) and os.path.isfile(comparator_component_report):
                compare_result = compare_components(comparatee_component_report, comparator_component_report)
                case_report["component_report"] = {
                    "tpl_tp": compare_result["tpl_tp"],
                    "tplv_tp": compare_result["tplv_tp"],
                    "tpl_fn": compare_result["tpl_fn"],
                    "tplv_fn": compare_result["tplv_fn"],
                    "tpl_fp": compare_result["tpl_fp"],
                    "tplv_fp": compare_result["tplv_fp"],
                    "tpl_tp_cnt": compare_result["tpl_tp_cnt"],
                    "tplv_tp_cnt": compare_result["tplv_tp_cnt"],
                    "tpl_fn_cnt": compare_result["tpl_fn_cnt"],
                    "tplv_fn_cnt": compare_result["tplv_fn_cnt"],
                    "tpl_fp_cnt": compare_result["tpl_fp_cnt"],
                    "tplv_fp_cnt": compare_result["tplv_fp_cnt"],
                    "R_TPL": compare_result["R_TPL"],
                    "P_TPL": compare_result["P_TPL"],
                    "R_TPLV": compare_result["R_TPLV"],
                    "P_TPLV": compare_result["P_TPLV"],
                }
            else:
                pretty_log(f"don't have {comparatee_component_report} or {comparator_component_report}", 'WARNING')

            if os.path.isfile(comparatee_issue_report) and os.path.isfile(comparator_issue_report):
                compare_result = compare_issues(comparatee_issue_report, comparator_issue_report)
                case_report["issue_report"] = {
                    "unique_cve_tp": compare_result['unique_cve_tp'],
                    "unique_cve_fn": compare_result['unique_cve_fn'],
                    "unique_cve_fp": compare_result['unique_cve_fp'],
                    "gav_cve_tp": compare_result['gav_cve_tp'],
                    "gav_cve_fn": compare_result['gav_cve_fn'],
                    "gav_cve_fp": compare_result['gav_cve_fp'],
                    "unique_cve_tp_cnt": compare_result['unique_cve_tp_cnt'],
                    "unique_cve_fn_cnt": compare_result['unique_cve_fn_cnt'],
                    "unique_cve_fp_cnt": compare_result['unique_cve_fp_cnt'],
                    "gav_cve_tp_cnt": compare_result['gav_cve_tp_cnt'],
                    "gav_cve_fn_cnt": compare_result['gav_cve_fn_cnt'],
                    "gav_cve_fp_cnt": compare_result['gav_cve_fp_cnt'],
                    "R_U_CVE": compare_result['R_U_CVE'],
                    "P_U_CVE": compare_result['P_U_CVE'],
                    "R_GAV_CVE": compare_result['R_GAV_CVE'],
                    "P_GAV_CVE": compare_result['P_GAV_CVE'],
                }
            else:
                pretty_log(f"don't have {comparatee_issue_report} or {comparator_issue_report}", 'WARNING')
            current_report["report_per_case"].append(case_report)

            testsuite_report_summary_path = os.path.join(working_dir,report_folder_name, f"{comparator}-{comparatee}-summary.json")
            pretty_log(f"saving report to {testsuite_report_summary_path}")
            pathlib.Path(testsuite_report_summary_path).parent.mkdir(parents=True, exist_ok=True)
            if os.path.isfile(testsuite_report_summary_path):
                os.remove(testsuite_report_summary_path)
            with open(testsuite_report_summary_path, "w") as outfile:
                json.dump(current_report, outfile)


def clear_json(working_dir, report_folder_name):
    for file in os.listdir(os.path.join(working_dir, report_folder_name)):
        if file.endswith(".json"):
            os.remove(os.path.join(working_dir, report_folder_name, file))


if __name__ == '__main__':
    manifest_csv_path = f"/root/SCAEvaluation/testsuite2/manifest-testsuite2.csv"
    manifest_csv = open(manifest_csv_path, 'r')
    csv_reader = csv.DictReader(manifest_csv)
    comparator_list = ['groundtruth']
    for row in csv_reader:
        working_dir = row['working_path']
        test_case = row['target']
        scan_type = row['type']
        if scan_type == "source":
            comparatee_list = ['scantist', 'whitesource', 'owasp','steady', 'ossindex']
            report_folder_name = "source_report"
            clear_json(working_dir, report_folder_name)
            generate_sca_tools_report(working_dir, report_folder_name, comparator_list, comparatee_list, test_case)
            report_folder_name = "intersect_report"
            clear_json(working_dir, report_folder_name)
            generate_sca_tools_report(working_dir, report_folder_name, comparator_list, comparatee_list, test_case)
        elif scan_type == 'saas':
            comparatee_list = ['scantist', 'dependabot', 'snyk']
            report_folder_name = "saas_report"
            clear_json(working_dir, report_folder_name)
            generate_sca_tools_report(working_dir, report_folder_name, comparator_list, comparatee_list, test_case)
            report_folder_name = "saas_intersect_report"
            clear_json(working_dir, report_folder_name)
            generate_sca_tools_report(working_dir, report_folder_name, comparator_list, comparatee_list, test_case)