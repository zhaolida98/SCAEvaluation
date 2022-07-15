import csv
import os
from util.utils import pretty_log, exec_command
from util.depUtils import build_mvn_project


projects_space = "/root/SCAEvaluation/large_scale/projects"
collection_csv_path = '/root/SCAEvaluation/large_scale/manifest/collection.csv'
manifest_csv_path = '/root/SCAEvaluation/large_scale/manifest/manifest.csv'

collection_csv = open(collection_csv_path, 'r')
manifest_csv = open(manifest_csv_path, 'a+')
reader = csv.DictReader(collection_csv)
writer = csv.DictWriter(manifest_csv, ['local_name', 'working_path','raw_name','status'])
writer.writeheader()

for cnt, item in enumerate(reader):
    raw_name = item['name']
    local_name = raw_name.replace('/', '@')
    print(f"processing on {raw_name}, cnt: {cnt}")
    project_dir = os.path.join(projects_space, local_name)
    clone_ok = True
    if os.path.isdir(project_dir):
        cmd = f"cd {project_dir} && git pull"
    else:
        cmd = f"cd {projects_space} && git clone https://github.com/{raw_name}.git {local_name}"
    res = exec_command(cmd)
    if res.get('code') != 0:
        clone_ok = False
        print(f"\nclone {raw_name} failed")
        
    build_ok = build_mvn_project(project_dir)
    
    tmp_item = {
        'local_name': local_name,
        'raw_name': raw_name,
        'working_path': project_dir,
        'status': "success" if clone_ok and build_ok else "failed"
    }
    writer.writerow(tmp_item)
    if not build_ok or not clone_ok:
        os.removedirs(project_dir) 
collection_csv.close()
manifest_csv.close()



