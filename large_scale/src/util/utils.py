import subprocess
import time
import traceback
import os
import csv
from .ComponentReport import ComponentReport
from .ComponentReport import field_names as component_field_names
from .IssueReport import IssueReport
from .IssueReport import field_names as issue_field_names


def pretty_log(log, logtype="INFO"):
    print(f'[{logtype}] {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}| {log}')


def exec_command(cmd, work_dir="."):
    if cmd == "" or cmd is None:
        return {"output": "", "code": 0}
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=work_dir
    )
    return_code = 0
    try:
        out, err = p.communicate()
        return_code = p.returncode
        if err:
            return {"error": err, "output": out.strip(), "code": return_code}
    except Exception as e:
        return {"error": traceback.format_exc(), "code": return_code}
    return {"output": out.strip(), "code": return_code}

def write_component_report(component_dict_list, report_name, output_dir):
    field_names = component_field_names
    try:
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        with open(f"{output_dir}/{report_name}.csv", mode="w", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=field_names)
            writer.writeheader()
            writer.writerows(component_dict_list)
    except:
        raise IOError(f"write component report for {report_name} failed.")
    pretty_log(f"write result to {output_dir}/{report_name}.csv")
    return os.path.join(output_dir, report_name)



def write_issue_report(issue_dict_list, report_name, output_dir):
    field_names = issue_field_names
    try:
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        with open(f"{output_dir}/{report_name}.csv", mode="w", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=field_names)
            writer.writeheader()
            writer.writerows(issue_dict_list)
    except:
        raise IOError(f"write issue report for {report_name} failed.")
    pretty_log(f"write result to {output_dir}/{report_name}.csv")
    return os.path.join(output_dir, report_name)