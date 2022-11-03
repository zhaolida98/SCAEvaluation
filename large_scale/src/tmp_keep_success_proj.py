import csv, json

name_set = []
content = {}
with open('/home/lida/SCAEvaluation-main/large_scale/manifest/build_status.csv', 'r') as j:
    csv_reader2 = csv.DictReader(j)
    for i in csv_reader2:
        if i['status'] == 'success':
            name_set.append(i)

with open('/home/lida/SCAEvaluation-main/large_scale/manifest/gt_gen_status.json', 'r') as f:
    content = json.load(f)
    

with open('/home/lida/SCAEvaluation-main/large_scale/manifest/build_manifest.csv', 'w') as k:
    csv_writer = csv.DictWriter(k, ['type','target','working_path'])
    csv_writer.writeheader()
    for i in name_set:
        if content[i['local_name']]['generate_gt_ok'] == True:
            csv_writer.writerow({
                'type': 'build',
                'target': i['local_name'],
                'working_path': i['working_path']
            })



