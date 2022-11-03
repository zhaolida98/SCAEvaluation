# given a list of verified vulnerable lib, find the list of projects that contain the libs, and also give a number that how many lib are matched.
import os, json, csv
base_report_path = '/home/lida/SCAEvaluation-main/large_scale/reports'
output_json = '/home/lida/SCAEvaluation-main/large_scale/manifest/shaded_collection.json'

# /home/lida/SCAEvaluation-main/large_scale/reports/0nise@burp-fofa/groundtruth/groundtruth-component-0nise@burp-fofa.csv

valid_repo = {}
for idx, proj_name in enumerate(os.listdir(base_report_path)):
    print("processing", idx)
    groundtruth_json = os.path.join(base_report_path, proj_name, 'groundtruth', f'report_{proj_name}.json')
    if not os.path.isfile(groundtruth_json):
        continue
    gt = json.load(open(groundtruth_json))
    related_list = gt['shaded'].keys()
    if len(related_list) > 0:
        
    tmp_verified_lib_list = []
    for gt_dep in related_list:
        tmp_gav = gt_dep.split(':')
        if len(tmp_gav) == 3:
            g, a, v = tmp_gav[0], tmp_gav[1], tmp_gav[2]
            if f'{g}_{a}' in verified_json and f'{a}-{v}' in verified_json[f'{g}_{a}']:
                tmp_verified_lib_list.append(f"{g}:{a}:{v}")
    if len(tmp_verified_lib_list) != 0:
        valid_repo[proj_name.replace('@', '/')] = tmp_verified_lib_list

with open(output_json, 'w') as f:
    json.dump(valid_repo, f)


    