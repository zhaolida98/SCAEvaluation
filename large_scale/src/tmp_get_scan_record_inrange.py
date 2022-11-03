# go through all status file and find the projects that all tools succeed
import csv
target_folder = '/home/lida/SCAEvaluation-main/large_scale/manifest_inrange'
status_csv_list = [
    "/home/lida/SCAEvaluation-main/large_scale/manifest/dependabot_scan_status.csv",
    '/home/lida/SCAEvaluation-main/large_scale/manifest/scantist_prebuild_scan_status.csv',
    '/home/lida/SCAEvaluation-main/large_scale/manifest/snyk_status.csv',
    '/home/lida/SCAEvaluation-main/large_scale/manifest/owasp_scan_status.csv',
    '/home/lida/SCAEvaluation-main/large_scale/manifest/scantist_scan_status.csv',
    '/home/lida/SCAEvaluation-main/large_scale/manifest/steady_scan_status.csv',
    '/home/lida/SCAEvaluation-main/large_scale/manifest/ossindex_scan_status.csv'
]
build_status = '/home/lida/SCAEvaluation-main/large_scale/manifest/build_manifest.csv'
build_proj_list = []
with open(build_status, 'r') as f:
    csvreader = csv.DictReader(f)
    for i in csvreader:
        build_proj_list.append(i['target'])
print(len(build_proj_list))
tmp_set = set()

for status_csv in status_csv_list:
    with open(status_csv, 'r') as f:
        content = f.readlines()
        for line in content:
            tmp_line = line.split(',')
            name = tmp_line[0].replace('/', '@')
            status = tmp_line[2]
            if status == "success" and name in build_proj_list:
                tmp_set.add(name)
    print(len(tmp_set), status_csv)
    tmp_set.clear()


# 3955
# 3925 /home/lida/SCAEvaluation-main/large_scale/manifest/dependabot_scan_status.csv
# 2437 /home/lida/SCAEvaluation-main/large_scale/manifest/scantist_prebuild_scan_status.csv
# 1509 /home/lida/SCAEvaluation-main/large_scale/manifest/snyk_status.csv
# 3641 /home/lida/SCAEvaluation-main/large_scale/manifest/owasp_scan_status.csv
# 796 /home/lida/SCAEvaluation-main/large_scale/manifest/scantist_scan_status.csv
# 228 /home/lida/SCAEvaluation-main/large_scale/manifest/steady_scan_status.csv
# 909 /home/lida/SCAEvaluation-main/large_scale/manifest/ossindex_status.csv
