import argparse
import os
import re

from util.utils import ComponentReport, exec_command, pretty_log
from util.utils import write_component_report


def generate_mvn_dep_tree_gt(mvn_dep_file_path, mvn_build_classpath, output_dir, name):
    assert os.path.isfile(mvn_dep_file_path)
    dep_dict = {}
    with open(mvn_dep_file_path, 'r') as file:
        content = file.read()
        dep_dict = parse_mvn_dependency_tree_output(content)
    with open(mvn_build_classpath, 'r') as file:
        content = file.read()
        dep_dict = parse_jars_in_mvn_build_classpath(content, dep_dict)
    write_component_report(list(dep_dict.values()), f"groundtruth-component-{name}", output_dir)


def parse_jars_in_mvn_build_classpath(content:str, dep_dict: dict):
    is_classPath = False
    avaliable_jar_paths = []
    # get jar paths and calculate the gav, if the gav is in dep_dict, then record the jar path for jar analysis
    for line in content.split(os.linesep):
        if line.startswith("[INFO] Dependencies classpath:"):
            is_classPath = True
            continue
        if is_classPath:
            is_classPath = False
            jar_paths = line.split(":")
            for jar_path in jar_paths:
                gav = get_GAV_from_jar_path(jar_path)
                if gav in dep_dict:
                    avaliable_jar_paths.append(jar_path)
    for avaliable_jar_path in avaliable_jar_paths:
        cmd = f"java -jar /root/ground-truth-generator.jar {avaliable_jar_path}"
        res = exec_command(cmd)
        if res.get('code') != 0:
            if 'output' in res:
                pretty_log(res['output'].decode(), 'ERROR')
            if 'error' in res:
                pretty_log(res['error'].decode(), 'ERROR')
            raise RuntimeError("parsing dependency:tree output error")
        result = res['output'].decode()
        for item in result.split(os.linesep):
            if not item:
                continue 
            print(item)
            gav, path_ref = item.split("@")
            gav_list = gav.split(":")
            comp = ComponentReport(":".join(gav_list[:-1]), gav_list[-1], "runtime-jar")
            comp.info['File Path'] = path_ref
            if comp.get_hash() not in dep_dict:
                dep_dict[comp.get_hash()] = comp.info
                print(comp.info)
    return dep_dict

def get_GAV_from_jar_path(jar_path):
    m2_home = os.path.join(".m2", "repository")
    if m2_home in jar_path:
        relative_jar_path = jar_path.split(m2_home)[1]
        tmp_list = relative_jar_path.split(os.sep)
        group_id = '.'.join(tmp_list[1:-3])
        artifact_id = tmp_list[-3]
        version = tmp_list[-2]
        gav = ":".join([group_id, artifact_id, version])
        return gav
    else:
        return os.path.basename(jar_path)        


def parse_mvn_dependency_tree_output(content: str):
    inDepSection = False
    under_unrelated_dep = False
    dep_dict = {}
    level_threshold = 0
    for line in content.split(os.linesep):
        line = line.replace('[INFO] ', '')
        if not line or "--------" in line:
            inDepSection = False
            continue
        if re.search('--- maven-dependency-plugin:\S*:tree', line):
            inDepSection = True
            continue
        if inDepSection:
            line, level = clean_line(line)
            # print(f"processing {line}")
            line_dep_dict = convert_line_to_dep(line, level)
            if "skip" in line_dep_dict:
                if "classifier" in line_dep_dict["skip"]:
                    level_threshold = level
                    under_unrelated_dep = True
                continue
            if under_unrelated_dep:
                if level_threshold < level:
                    continue
                else:
                    under_unrelated_dep = False
            if line_dep_dict:
                dep_dict[get_hash(line_dep_dict)] = line_dep_dict
    return dep_dict


def get_hash(dep_info):
    assert dep_info is not None
    return f"{dep_info['Library']}:{dep_info['Library Version']}"


def convert_line_to_dep(line: str, level: int):
    maven_parts = line.split(":")
    if len(maven_parts) < 4:
        raise AttributeError(f"maven parts should never below 4, line: {line}")

    group = maven_parts[0]
    artifact = maven_parts[1]
    version = ''
    scope = ''
    type = ''
    classifier = ''

    if len(maven_parts) == 4:
        type = maven_parts[-2]
        version = maven_parts[-1]
    elif len(maven_parts) == 5 or len(maven_parts) == 6:
        version = maven_parts[-2]
        scope = maven_parts[-1]
        type = maven_parts[2]
        if len(maven_parts) == 6:
            classifier = maven_parts[-3]

    else:
        raise AttributeError(f"maven parts should never above 6, line: {line}")

    if type in ['pom']:
        return {
            "skip":"type-pom"
        }

    if scope in ['', 'test', 'provided', 'system']:
        return {
            "skip": f"scope-{scope}"
        }

    if 'SNAPSHOT' in version:
        return {
            "skip":"version-SNAPSHOT"
        }

    if classifier in ['javadoc', 'test']:
        return {
            "skip":f"classifier-{classifier}"
        }

    tmp_dep = ComponentReport(f"{group}:{artifact}", version, scope)
    return tmp_dep.info


def clean_line(line:str):
    level = 0
    for pattern in ["+- ", "|  ", "\\- ", "   "]:
        while pattern in line:
            level += 1
            line = line.replace(pattern, "")
    # remove quote comment
    # +- org.glassfish.web:javax.servlet.jsp:jar:2.3.2:provided
    # |  \- org.glassfish:javax.el:jar:3.0.1-b12:provided (version selected from constraint [3.0.0,))
    line = line.split(' ')[0]
    return line, level


def is_line_related(line:str):
    if 'Download' in line or not line:
        return False
    if '[INFO]' not in line:
        return False
    return True


if __name__ == '__main__':
    # parser = argparse.ArgumentParser(description="transfer mvn dependency tree ourput to csv.")
    # parser.add_argument("dep_txt", type=str)
    # parser.add_argument("classpath_txt", type=str)
    # parser.add_argument("output", type=str)
    # parser.add_argument("name", type=str)
    # args = parser.parse_args()
    # mvn_dep_file_path = args.dep_txt
    # mvn_classpath = args.classpath_txt
    # output_dir = args.output
    # name = args.name
    repo_name = "dubbo"
    mvn_dep_file_path = f"/root/SCAEvaluation/testsuite2/SCAEvaluation-SAAS-Test@{repo_name}/SCAEvaluation-SAAS-Test@{repo_name}/dep.txt"
    mvn_classpath = f"/root/SCAEvaluation/testsuite2/SCAEvaluation-SAAS-Test@{repo_name}/SCAEvaluation-SAAS-Test@{repo_name}/classpath.txt"
    output_dir = f"/root/SCAEvaluation/testsuite2/SCAEvaluation-SAAS-Test@{repo_name}/source_report"
    name = f"groundtruth-component-SCAEvaluation-SAAS-Test@{repo_name}-new.csv"
    generate_mvn_dep_tree_gt(mvn_dep_file_path, mvn_classpath, output_dir, name)