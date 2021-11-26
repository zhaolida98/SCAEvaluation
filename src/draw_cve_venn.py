import json
import matplotlib.pyplot as plt
import venn
from venn import venn4
from venn._backwards_compatibility import vennx


def draw_cve_venn(cve_result_json):
    with open(cve_result_json, 'r') as cve_json:
        tmp_json = json.loads(cve_json.read())
        issue_block = tmp_json['common']['issue']
        scantist_issue = set()
        for issue in issue_block['scantist']:
            scantist_issue.add(issue['publicId'])

        steady_issue = set()
        for issue in issue_block['steady']:
            steady_issue.add(issue['publicId'])

        whitesource_issue = set()
        for issue in issue_block['whitesource']:
            whitesource_issue.add(issue['publicId'])

        owasp_issue = set()
        for issue in issue_block['owasp']:
            owasp_issue.add(issue['publicId'])
            
        # my_dpi = 100
        # plt.figure(figsize=(800 / my_dpi, 600 / my_dpi), dpi=my_dpi)  # 控制图尺寸的同时，使图高分辨率（高清）显示
        labels = venn.get_labels([scantist_issue, whitesource_issue, owasp_issue, steady_issue], fill=['number', 'logic'])
        fig, ax = venn.venn4(labels, names=['scantist', 'whitesource', 'owasp', 'steady'])
        fig.show()


if __name__ == '__main__':
    draw_cve_venn("/home/nryet/testProjects/SCAEvaluation/testsuit1/guava-23.0/source_report/cve_compare.json")
    # venn3(subsets=(20, 10, 12, 10, 9, 4, 3), set_labels=('Group A', 'Group B', 'Group C'), alpha=0.5)


