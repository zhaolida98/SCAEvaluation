import json
import os
import pathlib
import time
import csv
import argparse


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
            raw_library = row["Library"].replace("None", "").strip().lower().strip('-')

            if " " in raw_library:
                raw_lib, raw_org = raw_library.replace(": ", ":").split(" ")
                raw_lib = raw_lib.strip('-')
                raw_library = f"{raw_org}:{raw_lib}"
            # if row["Status"] != "matched":
                # continue
            libraries.append(raw_library)
            libraryversions.append("#".join([raw_library, row["Version"]]))

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
            # if row["Status"] != "matched":
                # continue
            cve_list.append(row["Public ID"])
            libraryversion_list.append("#".join([row["Library"], row["Library Version"]]))
    result = {
        "cve": {"details": cve_list, "count": len(cve_list)},
        "library_versions": {"details": list(set(libraryversion_list)), "count": len(set(libraryversion_list))}
    }
    pretty_log(f"finished processing {issue_report_path}, {line_count} lines, find {len(cve_list)} cves")
    # pretty_log(f"{issue_report_path} result: {result}")
    return result


def compare_issues(sca_issue_report_path, groundtruth_issue_report_path):
    sca_issue = get_issue_report_detail(sca_issue_report_path)
    groundtruth_issue = get_issue_report_detail(
        groundtruth_issue_report_path
    )
    tpcve_tp = set(sca_issue["cve"]["details"]).intersection(
        set(groundtruth_issue["cve"]["details"])
    )
    tpcve_fn = set(groundtruth_issue["cve"]["details"]).difference(
        set(sca_issue["cve"]["details"])
    )
    tpcve_fp = set(sca_issue["cve"]["details"]).difference(
        set(groundtruth_issue["cve"]["details"])
    )
    P_TPCVE = len(tpcve_tp) / sca_issue["cve"]["count"] \
        if sca_issue["cve"]["count"] != 0 else -1
    R_TPCVE = len(tpcve_tp) / groundtruth_issue["cve"]["count"] \
        if groundtruth_issue["cve"]["count"] != 0 else -1
    return {
        "sca_issues": sca_issue,
        "groundtruth_issues": groundtruth_issue,
        "tpcve_tp": list(tpcve_tp),
        "tpcve_fn": list(tpcve_fn),
        "tpcve_fp": list(tpcve_fp),
        "tpcve_tp_cnt": len(list(tpcve_tp)),
        "tpcve_fn_cnt": len(list(tpcve_fn)),
        "tpcve_fp_cnt": len(list(tpcve_fp)),
        "R_TPCVE": R_TPCVE,
        "P_TPCVE": P_TPCVE,
    }


def pretty_log(log, logtype="INFO"):
    print(f'[{logtype}] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}| {log}')


def generate_sca_tools_report(comparator_report, comparatee_report, name='summary', output=''):
    comparator = os.path.basename(comparator_report).split("-")[0]
    comparatee = os.path.basename(comparatee_report).split("-")[0]
    current_report = {
        "comparator": os.path.basename(comparator_report),
        "comparatee": os.path.basename(comparatee_report),
        "report_per_case": [],
    }

    case_report = {
        "component_report": {},
        "issur_report": {},
    }
    if 'component' in comparatee_report and 'component' in comparator_report:
        if os.path.isfile(comparatee_report) and os.path.isfile(comparator_report):
            compare_result = compare_components(comparatee_report, comparator_report)
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
            pretty_log(f"{comparatee_report} is file {os.path.isfile(comparatee_report)}")
            pretty_log(f"{comparator_report} is file {os.path.isfile(comparator_report)}")
    elif 'issue' in comparatee_report and 'issue' in comparator_report:
        if os.path.isfile(comparatee_report) and os.path.isfile(comparator_report):
            compare_result = compare_issues(comparatee_report, comparator_report)
            case_report["issur_report"] = {
                "tpcve_tp": compare_result["tpcve_tp"],
                "tpcve_fn": compare_result["tpcve_fn"],
                "tpcve_fp": compare_result["tpcve_fp"],
                "tpcve_tp_cnt": compare_result["tpcve_tp_cnt"],
                "tpcve_fn_cnt": compare_result["tpcve_fn_cnt"],
                "tpcve_fp_cnt": compare_result["tpcve_fp_cnt"],
                "R_TPCVE": compare_result["R_TPCVE"],
                "P_TPCVE": compare_result["P_TPCVE"],
            }
        else:
            pretty_log(f"{comparatee_report} is file {os.path.isfile(comparatee_report)}")
            pretty_log(f"{comparator_report} is file {os.path.isfile(comparator_report)}")
    else:
        pretty_log(f"{comparatee_report} or {comparator_report} format not allowed", 'WARNING')
    current_report["report_per_case"].append(case_report)

    testsuite_report_summary_path = os.path.join(output, f"{comparator}-{comparatee}-{name}.json")
    pretty_log(f"saving report to {testsuite_report_summary_path}")
    pathlib.Path(testsuite_report_summary_path).parent.mkdir(parents=True, exist_ok=True)
    if os.path.isfile(testsuite_report_summary_path):
        os.remove(testsuite_report_summary_path)
    with open(testsuite_report_summary_path, "w") as outfile:
        json.dump(current_report, outfile)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="transfer mvn dependency tree ourput to csv.")
    parser.add_argument("comparator_report_path", type=str)
    parser.add_argument("comparatee_report_path", type=str)
    parser.add_argument("-name", type=str)
    parser.add_argument("-output", type=str)
    args = parser.parse_args()
    comparator_report_path = args.comparator_report_path
    comparatee_report_path = args.comparatee_report_path
    name = args.name
    output = args.output
    generate_sca_tools_report(comparator_report_path, comparatee_report_path, name, output)