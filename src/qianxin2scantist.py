import csv


def trans_qianxin_scantist_component_report(qianxin_component_report, scantist_component_output):
    q_comp = open(qianxin_component_report, 'r')
    s_comp = open(scantist_component_output, 'w')
    csv_reader = csv.DictReader(q_comp)
    item_list = []
    for row in csv_reader:
        GAV = row['GAV坐标']
        GAV_list = GAV.split(',')

        if len(GAV_list) >1:
            for gav in GAV_list:
                group_id, artifact_id, version = gav.split(':')
                item_list.append({'Library': f'{artifact_id} {group_id}',
                                  'Version': version})
        else:
            group_id, artifact_id, version = GAV.split(':')
            item_list.append({'Library': f'{artifact_id} {group_id}',
                              'Version': version})

    field = ['Library', 'Version']
    csv_writer = csv.DictWriter(s_comp, field)
    csv_writer.writeheader()
    csv_writer.writerows(item_list)
    
def trans_qianxin_scantist_issue_report(qianxin_issue_report, scantist_issue_output):
    q_comp = open(qianxin_issue_report, 'r')
    s_comp = open(scantist_issue_output, 'w')
    csv_reader = csv.DictReader(q_comp)
    item_list = []
    for row in csv_reader:
        GAV = row['GAV坐标']
        public_id = row['CVE编号']
        GAV_list = GAV.split(',')
        if len(GAV_list) >1:
            for gav in GAV_list:
                group_id, artifact_id, version = gav.split(':')
                item_list.append({'Library': f'{artifact_id} {group_id}',
                                  'Library Version': version,
                                 'Public ID': public_id})
        else:
            group_id, artifact_id, version = GAV.split(':')
            item_list.append({'Library': f'{artifact_id} {group_id}',
                              'Library Version': version,
                              'Public ID': public_id})

    field = ['Library', 'Library Version', 'Public ID']
    csv_writer = csv.DictWriter(s_comp, field)
    csv_writer.writeheader()
    csv_writer.writerows(item_list)


if __name__ == '__main__':
    qianxin_component_report = "/home/nryet/testProjects/srcTest/mall-swarm-master/scantist_report/mall-swarm/source_report/qianxin-raw-component-mall-swarm.csv"
    scantist_component_output = "/home/nryet/testProjects/srcTest/mall-swarm-master/scantist_report/mall-swarm/source_report/qianxin-component-mall-swarm.csv"
    qianxin_issue_report = "/home/nryet/testProjects/srcTest/mall-swarm-master/scantist_report/mall-swarm/source_report/qianxin-raw-issue-mall-swarm.csv"
    scantist_issue_output = "/home/nryet/testProjects/srcTest/mall-swarm-master/scantist_report/mall-swarm/source_report/qianxin-issue-mall-swarm.csv"
    trans_qianxin_scantist_component_report(qianxin_component_report, scantist_component_output)
    trans_qianxin_scantist_issue_report(qianxin_issue_report, scantist_issue_output)
