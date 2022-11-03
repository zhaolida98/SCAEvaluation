# generate a groundtruth json from the dep.txt and classpath.txt
import argparse
import os
import re
import json
from util.issueUtils import get_issue_list_with_cache
from util.utils import exec_command, pretty_log

shadedjar_cache_path = "/home/lida/SCAEvaluation-main/large_scale/cache/shadedjar_cache.json"
cve_cache_path = "/home/lida/SCAEvaluation-main/large_scale/cache/cve_cache.json"
gt_generator_path = "/home/lida/SCAEvaluation-main/ground-truth-generator.jar"

def generate_mvn_dep_tree_gt(mvn_dep_file_path, mvn_build_classpath, output_dir, name):
    assert os.path.isfile(mvn_dep_file_path)
    # shaded jar cache
    shadedjar_cache = {}
    try: 
        if os.path.isfile(shadedjar_cache_path):
            with open(shadedjar_cache_path,'r') as cache_file:
                shadedjar_cache = json.load(cache_file)
        
        dep_dict = {
            "related" : {},
            "unrelated": {},
            "shaded": {},
            "summary": {}
        }
        with open(mvn_dep_file_path, 'r') as file:
            content = file.read()
            dep_dict = parse_mvn_dependency_tree_output(content, dep_dict)
        with open(mvn_build_classpath, 'r') as file:
            content = file.read()
            dep_dict = parse_jars_in_mvn_build_classpath(content, dep_dict, shadedjar_cache)
        # dep_dict = get_cve_list(dep_dict)
        dep_dict = make_summary(dep_dict)
        with open(os.path.join(output_dir, f"report_{name}.json"), 'w') as f:
            json.dump(dep_dict, f)
            pretty_log(f"dump json for {output_dir}")

        return True
    except Exception as e:
        pretty_log(f"generate_mvn_dep_tree_gt | error {e}")
        return False
    finally:
        with open(shadedjar_cache_path, 'w') as f:
            json.dump(shadedjar_cache, f)
            pretty_log("process finished, saving the shaded jar to cache")



def get_cve_list(dep_dict: dict):
    cve_cache_json = {}
    if os.path.isfile(cve_cache_path):
        with open(cve_cache_path, 'r') as f:
            cve_cache_json = json.loads(f.read())
    try: 
        for related_dep in dep_dict["related"]:
            cve_list = get_issue_list_with_cache(related_dep, cve_cache_json)
            dep_dict['related'][related_dep]['cve_list'] = cve_list
        for unrelated_dep in dep_dict["unrelated"]:
            cve_list = get_issue_list_with_cache(unrelated_dep, cve_cache_json)
            dep_dict['unrelated'][unrelated_dep]['cve_list'] = cve_list
        for shaded_dep in dep_dict["shaded"]:
            cve_list = get_issue_list_with_cache(shaded_dep, cve_cache_json)
            dep_dict['shaded'][shaded_dep]['cve_list'] = cve_list
    except Exception as e:
        pretty_log("get_cve_list | error")
        pass
    finally:
        with open(cve_cache_path, 'w') as f:
            json.dump(cve_cache_json, f)
            pretty_log("process finished, saving the cve to cache")
    return dep_dict


def make_summary(dep_dict: dict):
    related_cve_cnt = 0
    unrelated_cve_cnt = 0
    shaded_cve_cnt = 0
    for related_dep in dep_dict["related"]:
        related_cve_cnt += len(dep_dict["related"][related_dep]["cve_list"])
    for unrelated_dep in dep_dict["unrelated"]:
        unrelated_cve_cnt += len(dep_dict["unrelated"][unrelated_dep]["cve_list"])
    for shaded_dep in dep_dict["shaded"]:
        shaded_cve_cnt += len(dep_dict["shaded"][shaded_dep]["cve_list"])

    dep_dict["summary"] = {
        "related_cmp_cnt": len(dep_dict['related']),
        "unrelated_cmp_cnt": len(dep_dict['unrelated']),
        "shaded_cmp_cnt": len(dep_dict['shaded']),
        "related_cve_cnt": related_cve_cnt,
        "unrelated_cve_cnt": unrelated_cve_cnt,
        "shaded_cve_cnt": shaded_cve_cnt,
    }
    return dep_dict


def parse_jars_in_mvn_build_classpath(content:str, dep_dict: dict, shadedjar_cache: dict):
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
                if gav in dep_dict['related']:
                    avaliable_jar_paths.append(jar_path)
    for avaliable_jar_path in avaliable_jar_paths:
        if avaliable_jar_path in shadedjar_cache:
            result = shadedjar_cache[avaliable_jar_path]
        else:
            print('miss cache', avaliable_jar_path)
            cmd = f"java -jar {gt_generator_path} {avaliable_jar_path}"
            res = exec_command(cmd)
            if res.get('code') != 0:
                if 'output' in res:
                    pretty_log(res['output'].decode(), 'ERROR')
                if 'error' in res:
                    pretty_log(res['error'].decode(), 'ERROR')
                raise RuntimeError("parsing dependency:tree output error")
            result = res['output'].decode().split(os.linesep)
            shadedjar_cache[avaliable_jar_path] = result
        for item in result:
            if not item:
                continue 
            gav, path_ref = item.split("@")
            tmp_dep = {
                "gav": gav,
                "scope": "shaded",
                "classifier": "",
                "type": "",
                "exclude_reason": '',
                "path": path_ref,
                "cve_list": []
            }
            add_to_report(dep_dict, tmp_dep)
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


def parse_mvn_dependency_tree_output(content: str, dep_dict: dict):
    inDepSection = False
    under_unrelated_dep = False
    parents_classifier = ''
    parents_type = ''
    level_threshold = 0
    for line in content.split(os.linesep):
        line = line.replace('[INFO] ', '')
        if not line or "--------" in line:
            inDepSection = False
            continue
        if "Downloading" in line:
            continue
        if re.search('--- maven-dependency-plugin:\S*:tree', line):
            inDepSection = True
            continue
        if inDepSection:
            line, level = clean_line(line)
            # print(f"processing {line}")
            tmp_dep = convert_line_to_dep(line, level)
            if tmp_dep is None:
                continue
            if tmp_dep['classifier'] in ['javadoc', 'tests', 'sources', 'test', 'source']:
                level_threshold = level
                under_unrelated_dep = True
                parents_classifier = tmp_dep['classifier']
            if tmp_dep['type'] in ['java-source', 'test-jar','javadoc']:
                level_threshold = level
                under_unrelated_dep = True
                parents_type = tmp_dep['type']
                
            if under_unrelated_dep:
                if level_threshold < level:
                    tmp_dep['exclude_reason'] = f"parent classifier {parents_classifier} parent type {parents_type}"
                else:
                    under_unrelated_dep = False
            add_to_report(dep_dict, tmp_dep)
    return dep_dict


def get_hash(dep_info):
    assert dep_info is not None
    return f"{dep_info['Library']}:{dep_info['Library Version']}"


def convert_line_to_dep(line: str, level: int):
    maven_parts = line.split(":")
    if len(maven_parts) < 4:
        return None

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
        pretty_log(f"maven parts should never above 6, line: {line}")
        return None
    tmp_dep = {
        "gav": f"{group}:{artifact}:{version}",
        "scope": scope,
        "classifier": classifier,
        "type": type,
        "exclude_reason": '',
        "cve_list": []
    }
    return tmp_dep


def add_to_report(total_dep, tmp_dep):
    assert 'related' in total_dep
    assert 'unrelated' in total_dep
    assert 'shaded' in total_dep
    assert 'summary' in total_dep

    gav = tmp_dep['gav']
    type = tmp_dep['type']
    scope = tmp_dep['scope']
    classifier = tmp_dep['classifier']
    exclude_reason = tmp_dep['exclude_reason']

    if type in ['pom', 'java-source', 'test-jar','javadoc']:
        total_dep['unrelated'][gav] = tmp_dep
    elif scope in ['test', 'provided', 'system']:
        total_dep['unrelated'][gav] = tmp_dep
    elif classifier in ['javadoc', 'tests', 'sources', 'test', 'source']:
        total_dep['unrelated'][gav] = tmp_dep
    elif "parent classifier" in exclude_reason or 'parent type' in exclude_reason:
        total_dep['unrelated'][gav] = tmp_dep
    elif scope == 'shaded':
        if gav in total_dep['related']:
            return
        total_dep['shaded'][gav] = tmp_dep
    else:
        total_dep['related'][gav] = tmp_dep


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
    parser = argparse.ArgumentParser(description="transfer mvn dependency tree ourput to csv.")
    parser.add_argument("dep_txt", type=str)
    parser.add_argument("classpath_txt", type=str)
    parser.add_argument("output", type=str)
    parser.add_argument("name", type=str)
    args = parser.parse_args()
    mvn_dep_file_path = args.dep_txt
    mvn_classpath = args.classpath_txt
    output_dir = args.output
    name = args.name
    
    
    # repo_name = "dubbo"
    # mvn_dep_file_path = f"/root/SCAEvaluation/testsuite2/SCAEvaluation-SAAS-Test@{repo_name}/SCAEvaluation-SAAS-Test@{repo_name}/dep.txt"
    # mvn_classpath = f"/root/SCAEvaluation/testsuite2/SCAEvaluation-SAAS-Test@{repo_name}/SCAEvaluation-SAAS-Test@{repo_name}/classpath.txt"
    # output_dir = f"/root/SCAEvaluation/large_scale/reports"
    # name = repo_name
    generate_mvn_dep_tree_gt(mvn_dep_file_path, mvn_classpath, output_dir, name)