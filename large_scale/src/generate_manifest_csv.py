import csv, os, json
# generate manifest files from gt_gen_status.json
# only projects generated ok are included

gt_status = "/home/lida/SCAEvaluation-main/large_scale/manifest/gt_gen_status.json"
build_manifest_csv = "/home/lida/SCAEvaluation-main/large_scale/manifest/build_manifest.csv"
prebuild_manifest_csv = "/home/lida/SCAEvaluation-main/large_scale/manifest/prebuild_manifest.csv"
project_path = '/home/lida/SCAEvaluation-main/large_scale/projects'


available_build_projects = []
available_prebuild_projects = []
with open(gt_status, 'r') as f:
    json_content = json.load(f)
    for k, v in json_content.items():
        if v['generate_gt_ok']:
            build_item = {
                "type": 'build',
                'target': k,
                'working_path': os.path.join(project_path, k)
            }

            prebuild_item = {
                "type": 'prebuild',
                'target': k.replace('@', '/'),
                'working_path': ''
            }
            available_build_projects.append(build_item)
            available_prebuild_projects.append(prebuild_item)

with open(build_manifest_csv, 'w') as f:
    field = ['type','target','working_path']
    writer = csv.DictWriter(f, field)
    writer.writeheader()
    writer.writerows(available_build_projects)
    print('write to ', build_manifest_csv)

with open(prebuild_manifest_csv, 'w') as f:
    field = ['type','target','working_path']
    writer = csv.DictWriter(f, field)
    writer.writeheader()
    writer.writerows(available_prebuild_projects)
    print('write to ', prebuild_manifest_csv)

