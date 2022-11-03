from xml.etree import ElementTree as et
import os
import json

root_folder = "/home/lida/SCAEvaluation-main/large_scale/projects"
load_count = False
with_path_cache = True
element_distribution = "./element_distribution.json"


def count_features(pom_path, total_count):
    pom_file = open(pom_path, 'r')
    pom_content = pom_file.read()

    ns = "http://maven.apache.org/POM/4.0.0"
    et.register_namespace('', ns)
    tree = et.ElementTree()
    tree.parse(pom_path)

    total_count['total_cnt'] += 1

    if "<dependencyManagement>" in pom_content:
        total_count["dependencyManagement_cnt"] += 1
    
    if "<exclusion>" in pom_content:
        total_count["exclusion_cnt"] += 1
    
    if "<parent>" in pom_content:
        total_count["parent_cnt"] += 1

    if "<modules>" in pom_content:
        total_count["aggregation_cnt"] += 1

    if "<profiles>" in pom_content:
        total_count["profiles_cnt"] += 1

    if "<optional>" in pom_content:
        total_count["optional_cnt"] += 1

    if "maven-shade-plugin" in pom_content \
        or "maven-assembly-plugin" in pom_content \
        or "maven-antrun-plugin" in pom_content:
        total_count["shaded_jar_cnt"] += 1



    version_list = get_version_list(tree)
    properties_name_list = get_property_name_list(tree)
    has_version_local_variable = False
    has_version_remote_variable = False
    has_version_range = False
    has_snapshot = False

    for version in version_list:
        if (not has_version_local_variable or not has_version_remote_variable) and  '$' in version:
            tmp_version = version[2: -1]
            if tmp_version in properties_name_list:
                has_version_local_variable = True
            else:
                has_version_remote_variable = True
        if has_version_range is False:
            if version == 'LATEST':
                has_version_range = True
            for notion in range_notion:
                if notion in version:
                    has_version_range = True
        if has_snapshot is False and 'snapshot' in version.lower():
            has_snapshot = True
    
    if has_version_local_variable:
        total_count["version_in_local_variable_cnt"] += 1

    if has_version_remote_variable:
        total_count["version_in_remote_variable_cnt"] += 1

    if has_version_range:
        total_count["version_range_cnt"] += 1

    if has_snapshot:
        total_count['unstable_version_cnt'] += 1


    type_list = get_type_list(tree)
    has_type_jar = False
    has_type_ejb = False
    has_type_ejb_client = False
    has_type_war = False
    has_type_ear = False
    has_type_rar = False
    has_type_pom = False
    has_type_testjar = False
    has_type_mvn_plugin = False
    has_type_source = False
    has_type_javadoc = False
    has_type_other = False
    for t in type_list:
        if t == 'ejb':
            has_type_ejb = True
        elif t == 'jar':
            has_type_jar = True
        elif t == 'ejb-client':
            has_type_ejb_client = True
        elif t == 'war':
            has_type_war = True
        elif t == 'ear':
            has_type_ear = True
        elif t == 'rar':
            has_type_rar = True
        elif t == 'pom':
            has_type_pom = True
        elif t == 'test-jar':
            has_type_testjar = True
        elif t == 'maven-plugin':
            has_type_mvn_plugin = True
        elif t == 'java-source':
            has_type_source = True
        elif t == 'javadoc':
            has_type_javadoc = True
        else:
            if t not in total_count['type_others'].keys():
                total_count['type_others'][t] = 0
            total_count['type_others'][t] += 1
            has_type_other = True

    if has_type_jar:
        total_count['type_jar'] += 1
    if has_type_ejb:
        total_count['type_ejb_cnt'] += 1
    if has_type_ejb_client:
        total_count['type_ejb_client_cnt'] += 1
    if has_type_war:
        total_count['type_war_cnt'] += 1
    if has_type_ear:
        total_count['type_ear_cnt'] += 1
    if has_type_rar:
        total_count['type_rar_cnt'] += 1
    if has_type_pom:
        total_count['type_pom_cnt'] += 1
    if has_type_testjar:
        total_count['type_test_jar_cnt'] += 1
    if has_type_mvn_plugin:
        total_count['type_mvn_plugin_cnt'] += 1
    if has_type_source:
        total_count['type_java_source_cnt'] += 1
    if has_type_javadoc:
        total_count['type_javadoc_cnt'] += 1
    if has_type_other:
        total_count['type_others_cnt'] += 1
      

    classifier_list = get_classifier_list(tree)
    has_classifier_sources = False
    has_classifier_javadoc = False
    has_classifier_tests = False
    has_classifier_client = False
    has_classifier_other = False

    for c in classifier_list:
        if 'sources' == c:
            has_classifier_sources = True
        elif 'javadoc' == c:
            has_classifier_javadoc = True
        elif 'tests' == c:
            has_classifier_tests = True
        elif 'client' == c:
            has_classifier_client = True
        else:
            if c not in total_count['classifier_others'].keys():
                total_count['classifier_others'][c] = 0
            total_count['classifier_others'][c] += 1
            has_classifier_other = True
    
    if has_classifier_sources:
        total_count['classifier_sources_cnt'] += 1
    if has_classifier_javadoc:
        total_count['classifier_javadoc_cnt'] += 1
    if has_classifier_tests:
        total_count['classifier_tests_cnt'] += 1
    if has_classifier_client:
        total_count['classifier_client_cnt'] += 1
    if has_classifier_other:
        total_count['classifier_others_cnt'] += 1

    scope_list = get_scope_list(tree)
    has_scope_runtime = False
    has_scope_provided = False
    has_scope_test = False
    has_scope_system = False

    for scope in scope_list:
        if 'runtime' == scope:
                has_scope_runtime = True
        elif 'provided' == scope:
                has_scope_provided = True
        elif 'test' == scope:
                has_scope_test = True
        elif 'system' == scope:
                has_scope_system = True
    
    if has_scope_runtime:
        total_count['scope_runtime_cnt'] += 1
    if has_scope_provided:
        total_count['scope_provided_cnt'] += 1
    if has_scope_test:
        total_count['scope_test_cnt'] += 1
    if has_scope_system:
        total_count['scope_system_cnt'] += 1
    pom_file.close()

    
def get_version_list(tree):
    version_list = []
    tmp = tree.findall(".//{http://maven.apache.org/POM/4.0.0}version")
    for i in tmp:
        if i is not None:
            version_list.append(i.text)
    return version_list

def get_type_list(tree):
    type_list = []
    tmp = tree.findall(".//{http://maven.apache.org/POM/4.0.0}type")
    for i in tmp:
        if i is not None:
            type_list.append(i.text)
    return type_list

def get_classifier_list(tree):
    classifier_list = []
    tmp = tree.findall(".//{http://maven.apache.org/POM/4.0.0}classifier")
    for i in tmp:
        if i is not None:
            classifier_list.append(i.text)
    return classifier_list

def get_scope_list(tree):
    scope_list = []
    tmp = tree.findall(".//{http://maven.apache.org/POM/4.0.0}scope")
    for i in tmp:
        if i is not None:
            scope_list.append(i.text)
    return scope_list

def get_property_name_list(tree):
    property_name_list = []
    tmp = tree.findall(".//{http://maven.apache.org/POM/4.0.0}properties")
    for i in tmp:
        for j in i.iter():
            property_name_list.append(j.tag.replace("{http://maven.apache.org/POM/4.0.0}", ""))
    return property_name_list

def walk_folders(root_dir, with_cache = True):
    path_cache = "./path_cache.json"
    path_cache_json = {}
    if os.path.isfile(path_cache):
        path_cache_json = json.loads(open(path_cache, 'r').read())
    if with_cache:
        if root_dir in path_cache_json:
            return path_cache_json[root_dir]
    pom_list = []
    for (root,dirs,files) in os.walk(root_dir, topdown=True):
        for f in files:
            if f.endswith(".pom") or f == "pom.xml":
                pom_list.append(os.path.join(root, f))
    path_cache_json[root_dir] = pom_list
    with open(path_cache, 'w') as f:
        json.dump(path_cache_json, f)
    return pom_list



    
if __name__ == "__main__":

    
    total_count = {
        "total_cnt": 0,
        "dependencyManagement_cnt": 0,
        "exclusion_cnt": 0,
        "parent_cnt": 0,
        "aggregation_cnt": 0,
        "profiles_cnt": 0,
        "optional_cnt": 0,
        "version_range_cnt": 0,
        "version_in_local_variable_cnt": 0,
        "version_in_remote_variable_cnt": 0,
        "unstable_version_cnt": 0,
        "shaded_jar_cnt": 0,
        "type_ejb_cnt": 0,
        "type_ejb_client_cnt": 0,
        "type_war_cnt": 0,
        "type_ear_cnt": 0,
        "type_rar_cnt": 0,
        "type_pom_cnt": 0,
        "type_test_jar_cnt": 0,
        "type_mvn_plugin_cnt": 0,
        "type_java_source_cnt": 0,
        "type_javadoc_cnt": 0,
        "type_others_cnt": 0,
        "classifier_sources_cnt": 0,
        "classifier_javadoc_cnt": 0,
        "classifier_tests_cnt": 0,
        "classifier_client_cnt": 0,
        "classifier_others_cnt": 0,
        "scope_runtime_cnt": 0,
        "scope_provided_cnt": 0,
        "scope_test_cnt": 0,
        "scope_system_cnt": 0,
        "type_others": {},
        "classifier_others": {}
    }
    if load_count:
        with open(element_distribution, 'r') as f:
            total_count = json.loads(f.read())
    range_notion = ['[', ']', '(', ')', '<', '>']

    pom_path_list = walk_folders(root_folder, with_path_cache)
    for i, pom_path in enumerate(pom_path_list):
        print(f"\r{i+1}/{len(pom_path_list)}: {pom_path}", end="", flush=True)
        try:
            count_features(pom_path, total_count)
        except Exception as e:
            print(e)
    print("finished", ' '*40)
    with open(element_distribution, 'w') as f:
        json.dump(total_count, f)

