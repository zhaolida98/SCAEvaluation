import os
from .utils import pretty_log, exec_command


def build_mvn_project(project_working_dir):
    cmd = f'cd {project_working_dir} && mvn install -Dmaven.test.skip'
    pretty_log(f"executing {cmd}")
    res = exec_command(cmd)
    build_ok = True
    if res.get('code') != 0:
        if 'output' in res:
            pretty_log(res['output'].decode(), 'ERROR')
        if 'error' in res:
            pretty_log(res['error'].decode(), 'ERROR')
        pretty_log("generate dependency:tree error. Make sure the project can be built")
        build_ok = False
    return build_ok


def generate_dep_tree(project_working_dir):
    # write dependency:tree to dep.txt
    dep_tree_txt = os.path.join(project_working_dir, "dep.txt")
    cmd = f'cd {project_working_dir} && mvn dependency:tree > {dep_tree_txt}'
    pretty_log(f"executing {cmd}")
    res = exec_command(cmd)
    dep_ok = True
    if res.get('code') != 0:
        if 'output' in res:
            pretty_log(res['output'].decode(), 'ERROR')
        if 'error' in res:
            pretty_log(res['error'].decode(), 'ERROR')
        pretty_log("generate dependency:tree error. Make sure the project can be built")
        dep_ok = False
    return dep_ok
    

def generate_class_path(project_working_dir):            
    # write dependency:class-buildpath to classpath.txt
    build_classpath_txt = os.path.join(project_working_dir, "classpath.txt")
    cmd = f'cd {project_working_dir} && mvn dependency:build-classpath > {build_classpath_txt}'
    pretty_log(f"executing {cmd}")
    res = exec_command(cmd)
    build_cp_ok = True
    if res.get('code') != 0:
        if 'output' in res:
            pretty_log(res['output'].decode(), 'ERROR')
        if 'error' in res:
            pretty_log(res['error'].decode(), 'ERROR')
        pretty_log("generate dependency:build-classpath error. Make sure the project can be built")
        build_cp_ok = False
    return build_cp_ok