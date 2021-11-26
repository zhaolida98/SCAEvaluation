import csv
import os
import re
import argparse



def write_component_report(info_list, report_name, output_dir):
    field_names = [
        "Library",
        "Depth",
        "Version",
        "Latest Version",
        "File Path",
        "Vulnerabilities",
        "License",
        "Popularity",
        "Recommended upgrade",
        "Vulnerability List",
    ]
    try:
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        with open(f"{output_dir}/{report_name}.csv", mode="w", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=field_names)
            writer.writeheader()
            writer.writerows(list(info_list.values()))
    except:
        raise IOError(f"write component report for {report_name} failed.")
    print(f"write result to {output_dir}/{report_name}.csv")

def generate_mvn_dep_tree_gt(mvn_dep_file_path, output_dir, name):
    assert os.path.isfile(mvn_dep_file_path)
    file = open(mvn_dep_file_path, 'r')
    content = file.read()
    dep_list = parse_mvn_dependency_tree_output(content)
    write_component_report(dep_list, f"groundtruth-component-{name}", output_dir)


def parse_mvn_dependency_tree_output(content: str):
    inDepSection = False
    dep_list = {}
    for line in content.split(os.linesep):
        line = line.replace('[INFO]', '').strip()
        if not line or "--------" in line:
            inDepSection = False
            continue
        if re.search('--- maven-dependency-plugin:\S*:tree', line):
            inDepSection = True
            continue
        if inDepSection:
            line = clean_line(line)
            # print(f"processing {line}")
            dep_dict = convert_line_to_dep(line)
            if dep_dict:
                dep_list[get_hash(dep_dict)] = dep_dict
    return dep_list


def get_hash(dep_dict):
    assert dep_dict is not None
    return f"{dep_dict['Library']} {dep_dict['Version']}"


def convert_line_to_dep(line: str):
    maven_parts = line.split(":")
    if len(maven_parts) < 4:
        raise AttributeError(f"maven parts should never below 4, line: {line}")

    group = maven_parts[0]
    artifact = maven_parts[1]
    version = ''
    scope = ''

    if len(maven_parts) == 4:
        version = maven_parts[-1]
    elif len(maven_parts) == 5 or len(maven_parts) == 6:
        version = maven_parts[-2]
        scope = maven_parts[-1]
    else:
        raise AttributeError(f"maven parts should never above 6, line: {line}")

    if scope in ['test']:
        return None

    trm_dict = {
        "Library": f"{artifact} {group}",
        "Depth": "",
        "Version": version,
        "Latest Version": "",
        "File Path": "",
        "Vulnerabilities": "",
        "License": "",
        "Popularity": "",
        "Recommended upgrade": "",
        "Vulnerability List": [],
    }

    return trm_dict


def clean_line(line:str):
    for pattern in ["+- ", "|  ", "\\- ", "   "]:
        while pattern in line:
            line = line.replace(pattern, "")
    return line


def is_line_related(line:str):
    if 'Download' in line or not line:
        return False
    if '[INFO]' not in line:
        return False
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="transfer mvn dependency tree ourput to csv.")
    parser.add_argument("input", type=str)
    parser.add_argument("output", type=str)
    parser.add_argument("name", type=str)
    args = parser.parse_args()
    mvn_dep_file_path = args.input
    output_dir = args.output
    name = args.name
    generate_mvn_dep_tree_gt(mvn_dep_file_path, output_dir, name)