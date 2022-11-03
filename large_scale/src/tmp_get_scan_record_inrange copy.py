# go through all status file and find the projects that all tools succeed
import csv, os
from posixpath import basename
import random
target_folder = '/home/lida/SCAEvaluation-main/large_scale/manifest_inrange'
status_csv_list = [
    # "/home/lida/SCAEvaluation-main/large_scale/manifest/dependabot_scan_status.csv",
    '/home/lida/SCAEvaluation-main/large_scale/manifest/scantist_prebuild_scan_status.csv',
    # '/home/lida/SCAEvaluation-main/large_scale/manifest/snyk_status.csv',
    # '/home/lida/SCAEvaluation-main/large_scale/manifest/owasp_scan_status.csv',
    # '/home/lida/SCAEvaluation-main/large_scale/manifest/scantist_scan_status.csv',
    # '/home/lida/SCAEvaluation-main/large_scale/manifest/steady_scan_status.csv',
    # '/home/lida/SCAEvaluation-main/large_scale/manifest/ossindex_scan_status.csv'
]
build_status = '/home/lida/SCAEvaluation-main/large_scale/manifest/build_manifest.csv'
time_map = {
    'scantist': 209,
    'owasp': 105
}
build_proj_list = []
with open(build_status, 'r') as f:
    csvreader = csv.DictReader(f)
    for i in csvreader:
        build_proj_list.append(i['target'])

for status_csv in status_csv_list:
    status_csv_name = {}
    with open(status_csv, 'r') as f:
        lines = f.readlines()
        for i in lines:
            status_csv_name[i.split(',')[0]] = i

    valid_lines = []
    base_name = os.path.basename(status_csv)
    tool_name = base_name.split('_')[0]
    target_csv = os.path.join(target_folder, base_name)

    for build_proj in build_proj_list:
        if build_proj in status_csv_name:
            valid_lines.append(status_csv_name[build_proj])
        else:
            failed_line = f'{build_proj},{tool_name},failed,0,\n'
            # print(failed_line)
            valid_lines.append(failed_line)
    
    
    with open(target_csv, 'w') as f:
        f.writelines(valid_lines)
    print(base_name, len(valid_lines))



# 3955
# 3925 /home/lida/SCAEvaluation-main/large_scale/manifest/dependabot_scan_status.csv
# 2437 /home/lida/SCAEvaluation-main/large_scale/manifest/scantist_prebuild_scan_status.csv
# 1509 /home/lida/SCAEvaluation-main/large_scale/manifest/snyk_status.csv
# 3641 /home/lida/SCAEvaluation-main/large_scale/manifest/owasp_scan_status.csv
# 796 /home/lida/SCAEvaluation-main/large_scale/manifest/scantist_scan_status.csv
# 228 /home/lida/SCAEvaluation-main/large_scale/manifest/steady_scan_status.csv
# 909 /home/lida/SCAEvaluation-main/large_scale/manifest/ossindex_status.csv

# dependabot_scan_status.csv 3955
# scantist_prebuild_scan_status.csv 2764
# snyk_status.csv 1509
# owasp_scan_status.csv 3658
# scantist_scan_status.csv 1894
# steady_scan_status.csv 467
# ossindex_scan_status.csv 3955