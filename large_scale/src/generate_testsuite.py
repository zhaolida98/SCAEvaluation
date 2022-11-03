# clone and build the project collected in the colletion.csv, and record the build status
import csv
import os
from util.utils import exec_command
from util.depUtils import build_mvn_project
update_proj = False
skip_build = False

projects_space = "/home/lida/SCAEvaluation-main/large_scale/projects"
collection_csv_path = '/home/lida/SCAEvaluation-main/large_scale/manifest/collection.csv'
clone_csv_path = '/home/lida/SCAEvaluation-main/large_scale/manifest/build_status.csv'

collection_csv = open(collection_csv_path, 'r')
reader = csv.DictReader(collection_csv)

for cnt, item in enumerate(reader):
    if cnt<2889:
        continue
    raw_name = item['name']
    local_name = raw_name.replace('/', '@')
    print(f"processing on {raw_name}, cnt: {cnt}")
    project_dir = os.path.join(projects_space, local_name)
    clone_ok = True
    if os.path.isdir(project_dir):
        if update_proj:
            cmd = f"cd {project_dir} && git pull"
        else:
            tmp_item = {
                'local_name': local_name,
                'raw_name': raw_name,
                'working_path': project_dir,
                'status': "success"
            }
            cmd = ""
    else:
        cmd = f"cd {projects_space} && git clone --depth 1 https://foo:bar@github.com/{raw_name}.git {local_name}"
    res = exec_command(cmd)
    if res.get('code') != 0:
        clone_ok = False
        print(f"\nclone {raw_name} failed")
    else:
        print(f"clone {raw_name} success")
    if skip_build:
        build_ok = True
    else:
        build_ok = build_mvn_project(project_dir)
    
    tmp_item = {
        'local_name': local_name,
        'raw_name': raw_name,
        'working_path': project_dir,
        'status': "success" if clone_ok and build_ok else "failed"
    }
    with open(clone_csv_path, '+a') as f:
        writer1 = csv.DictWriter(f, ['local_name', 'working_path','raw_name','status'])
        writer1.writerow(tmp_item)
    
    # if not build_ok or not clone_ok:
        # os.removedirs(project_dir) 
collection_csv.close()




