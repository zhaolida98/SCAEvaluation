import os, csv, statistics

help_me_read_csv = '/home/lida/SCAEvaluation-main/large_scale/src/help_me_read.csv'

result = {
    'build' : {
        'ossindex': {'cmp_precision': 0, 'cmp_recall': 0, 'cve_precision': 0, 'cve_recall': 0},
        'owasp': {'cmp_precision': 0, 'cmp_recall': 0, 'cve_precision': 0, 'cve_recall': 0},
        'scantist': {'cmp_precision': 0, 'cmp_recall': 0, 'cve_precision': 0, 'cve_recall': 0},
        'steady': {'cmp_precision': 0, 'cmp_recall': 0, 'cve_precision': 0, 'cve_recall': 0}
    },
    'prebuild': {
        'dependabot': {'cmp_precision': 0, 'cmp_recall': 0, 'cve_precision': 0, 'cve_recall': 0},
        'scantist': {'cmp_precision': 0, 'cmp_recall': 0, 'cve_precision': 0, 'cve_recall': 0},
        'snyk': {'cmp_precision': 0, 'cmp_recall': 0, 'cve_precision': 0, 'cve_recall': 0}
    }
}

with open(help_me_read_csv, 'r') as f:
    csv_reader = csv.DictReader(f)
    content = [c for c in csv_reader]

for mode, tools in result.items():
    for tool in tools.keys():
        print(mode, tool)
        cmp_precision_list = []
        cmp_recall_list = []
        cve_precision_list = []
        cve_recall_list = []
        for i in content:
            report_type = i['report_type']
            tool_name = i['tool']
            if mode == report_type and tool == tool_name:
                cmptp, cmpfp, cmpfn = float(i['cmpt_tp']), float(i['cmpt_fp']), float(i['cmpt_fn'])
                cvetp, cvefp, cvefn = float(i['cve_tp']), float(i['cve_fp']), float(i['cve_fn'])
                if cmptp + cmpfp != 0:
                    cmp_precision = cmptp / (cmptp + cmpfp)
                    if cmp_precision != 0:
                        cmp_precision_list.append(cmp_precision)
                if cmptp + cmpfn != 0:
                    cmp_recall = cmptp / (cmptp + cmpfn)
                    if cmp_recall != 0:
                        cmp_recall_list.append(cmp_recall)

                if cvetp + cvefp != 0:
                    cve_precision = cvetp / (cvetp + cvefp)
                    if cve_precision != 0:
                        cve_precision_list.append(cve_precision)
                if cvetp + cvefn != 0:
                    cve_recall = cvetp / (cvetp + cvefn)
                    if cve_recall != 0:
                        cve_recall_list.append(cve_recall)
        result[mode][tool]['cmp_precision'] = statistics.mean(cmp_precision_list)
        result[mode][tool]['cmp_recall'] = statistics.mean(cmp_recall_list)
        if tool == 'dependabot':
            continue
        result[mode][tool]['cve_precision'] = statistics.mean(cve_precision_list)
        result[mode][tool]['cve_recall'] = statistics.mean(cve_recall_list)
print('{0:10}{1:10}{2:14}{2:14}{2:14}{3:14}{4:14}{5:14}'.format('mode','tool','cmp_precision','cmp_recall','cmp_f1','cve_precision','cve_recall','cve_f1'))
for mode, tools in result.items():
    for tool in tools.keys():
        cmp_precision = result[mode][tool]['cmp_precision'] 
        cmp_recall = result[mode][tool]['cmp_recall'] 
        cve_precision = result[mode][tool]['cve_precision'] 
        cve_recall = result[mode][tool]['cve_recall'] 
        if tool != 'dependabot':
            cmp_f1 = 2*cmp_precision*cmp_recall/(cmp_precision + cmp_recall)
            cve_f1 = 2*cve_precision*cve_recall/(cve_precision + cve_recall)
        print('{0:10}{1:10}{2:14.3f}{3:14.3f}{4:14.3f}{5:14.3f}{4:14.3f}{5:14.3f}'.format(mode,tool,cmp_precision,cmp_recall,cmp_f1,cve_f1, cve_precision,cve_recall))


# mode      tool      cmp_precision cmp_precision cmp_precision cmp_recall    cmp_f1        cve_precision 
# build     ossindex           0.997         0.836         0.909         0.598         0.909         0.598
# build     owasp              0.997         0.889         0.940         0.726         0.940         0.726
# build     scantist           0.998         0.759         0.862         0.936         0.862         0.936
# build     steady             0.996         0.736         0.846         0.361         0.846         0.361
# prebuild  dependabot         0.525         0.289         0.846         0.361         0.846         0.361
# prebuild  scantist           0.999         0.757         0.862         0.920         0.862         0.920
# prebuild  snyk               0.841         0.843         0.842         0.398         0.842         0.398


			