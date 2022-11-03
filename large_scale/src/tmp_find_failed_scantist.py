import csv, os, json
from genericpath import isfile
name_set = []
with open('/home/lida/SCAEvaluation-main/large_scale/manifest/build_manifest.csv', 'r') as j:
    csv_reader2 = csv.DictReader(j)
    for i in csv_reader2:
        name_set.append(i['target'])

base_proj_path = '/home/lida/SCAEvaluation-main/large_scale/projects'
base_repo_path = '/home/lida/SCAEvaluation-main/large_scale/reports'
cnt = 0
for idx, name in enumerate(name_set):
    dep_tree_json_path = os.path.join(base_proj_path, name, 'dependency-tree.json')
    if os.path.isfile(dep_tree_json_path):
        print('process on', idx, dep_tree_json_path)
        with open(dep_tree_json_path, 'r') as f:
            tree_json = f.read()
            if 'airgap' in tree_json:
                cnt += 1
                target_report_path = os.path.join(base_repo_path, name, 'build', f'groundtruth-scantist-summary.json')
                if os.path.isfile(target_report_path):
                    os.remove(target_report_path)

print(cnt)
print(len(name_set))