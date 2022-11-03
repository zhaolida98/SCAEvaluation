# go through all status file and find the projects that all tools succeed
import csv, os
import statistics as st 

status_csv_list = [
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

for status_csv in status_csv_list:
    tmp_time_list = []
    with open(status_csv, 'r') as f:
        content = f.readlines()
        for line in content:
            tmp_line = line.split(',')
            timespent = tmp_line[3]
            tmp_time_list.append(float(timespent))
    total_time = 0
    for t in tmp_time_list:
        total_time += t
    avg_time = st.mean(tmp_time_list)
    std_time = st.stdev(tmp_time_list)
    mid_time = st.median(tmp_time_list)
    print(f'avg:{avg_time}, mid:{mid_time}, std:{std_time} | {os.path.basename(status_csv)}')



# avg:105.04033639056901, mid:59.98397350311279, std:327.3660683730062 | owasp_scan_status.csv
# avg:208.79950427322424, mid:105.24019742012024, std:753.0330893666533 | scantist_scan_status.csv
# avg:2266.0542261031933, mid:411.30869603157043, std:6399.66429390599 | steady_scan_status.csv
# avg:77.09294990913801, mid:9.170344829559326, std:647.5229887582941 | ossindex_scan_status.csv
