# build the project that can successfully generate dep.txt and classpath.txt
import csv
import multiprocessing
import os
from util.depUtils import build_mvn_project

projects_space = "/home/lida/SCAEvaluation-main/large_scale/projects"
collection_csv_path = '/home/lida/SCAEvaluation-main/large_scale/manifest/build_manifest.csv'
build_status_path = '/home/lida/SCAEvaluation-main/large_scale/manifest/build_status.csv'

build_cache = set()
with open(build_status_path, 'r') as f:
    csv_reader = csv.DictReader(f)
    for item in csv_reader:
        build_cache.add(item['local_name'])

collection_csv = open(collection_csv_path, 'r')
reader = csv.DictReader(collection_csv)



def record_scan_status(build_status_dict):
    if build_status_dict is None:
        return
    with open(build_status_path, '+a') as f:
        writer1 = csv.DictWriter(f, ['local_name', 'working_path','raw_name','status'])
        writer1.writerow(build_status_dict)

def start_build(cnt, item):
    target_name = item['target']
    working_path = item['working_path']
    if target_name in ['snakerflow@snakerflow']:
        return None
    print(f"processing on {target_name}, cnt: {cnt}")
    if target_name in build_cache:
        print('skip', target_name)
        return None
    build_cache.add(target_name)
    build_ok = build_mvn_project(working_path)
    
    return {
        'local_name': target_name,
        'working_path': working_path,
        'raw_name': target_name.replace('@', '/'),
        'status': "success" if build_ok else "failed"
    }

pool = multiprocessing.Pool(8)
for cnt, item in enumerate(reader):
    pool.apply_async(func=start_build, args=(cnt, item, ), callback=record_scan_status)
    
collection_csv.close()
pool.close()
pool.join()




