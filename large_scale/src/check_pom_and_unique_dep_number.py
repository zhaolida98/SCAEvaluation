# check involved pom number and unique dep number
import csv, os, json

build_manifest = '/home/lida/SCAEvaluation-main/large_scale/manifest/build_manifest.csv'
report_path = '/home/lida/SCAEvaluation-main/large_scale/reports'

pom_num = 0
dep_set = set()

collection_csv = open(build_manifest, 'r')
reader = csv.DictReader(collection_csv)

for cnt, item in enumerate(reader):
    target_name = item['target']
    working_path = item['working_path']
    print(f"processing on {target_name}, cnt: {cnt}")
    for root, dirs, files in os.walk(working_path):
        for file in files:
            if file == 'pom.xml':
                pom_num += 1

    gt_report = os.path.join(report_path, target_name, 'groundtruth', f'report_{target_name}.json')
    with open(gt_report, 'r') as f:
        content = json.load(f)
        for i in content['related'].keys():
            dep_set.add(i)
        for i in content['unrelated'].keys():
            dep_set.add(i)
        for i in content['shaded'].keys():
            dep_set.add(i)
    
print('depset length:', len(dep_set))
print('pom num', pom_num)

# depset length: 73499
# pom num 21130