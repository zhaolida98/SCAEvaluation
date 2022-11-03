import os,shutil
from os.path import isfile
import csv,json

from util.ComponentReport import ComponentReport
from util.utils import write_component_report

report_root_folder = '/home/lida/SCAEvaluation-main/large_scale/reports'
manifest_csv = '/home/lida/SCAEvaluation-main/large_scale/manifest/prebuild_manifest.csv'
f = open(manifest_csv, 'r')
csvreader = csv.DictReader(f)
cnt = 0
for line in csvreader:
    name = line['target']
    cnt += 1
    username = name.split('/')[0]
    src = os.path.join(report_root_folder, username)
    print(cnt, " :processing on ", src)
    if os.path.isdir(src):
        shutil.rmtree(src)
    