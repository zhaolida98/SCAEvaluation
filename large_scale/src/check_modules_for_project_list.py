# go through all status file and find the projects that all tools succeed
import csv, os
target_folder = '/home/lida/SCAEvaluation-main/large_scale/manifest_inrange'
project_path = '/home/lida/SCAEvaluation-main/large_scale/projects'
status_csv_list = [
    '/home/lida/SCAEvaluation-main/large_scale/manifest/snyk_status.csv',
    '/home/lida/SCAEvaluation-main/large_scale/manifest/steady_scan_status.csv',
]
build_status = '/home/lida/SCAEvaluation-main/large_scale/manifest/build_manifest.csv'
build_proj_list = []
with open(build_status, 'r') as f:
    csvreader = csv.DictReader(f)
    for i in csvreader:
        build_proj_list.append(i['target'])
print(len(build_proj_list))

for status_csv in status_csv_list:
    proj_cnt = 0
    pom_cnt = 0
    with open(status_csv, 'r') as f:
        content = f.readlines()
        for line in content:
            tmp_line = line.split(',')
            name = tmp_line[0].replace('/', '@')
            status = tmp_line[2]
            if name in build_proj_list:
                working_path = os.path.join(project_path, name)
                proj_cnt += 1
                # for root, dirs, files in os.walk(working_path):
                    # if 'pom.xml' in files:
                        # pom_cnt += 1
    
    base_name = os.path.basename(status_csv)
    print(base_name, pom_cnt, proj_cnt)
    # 1509 11449
    # 4