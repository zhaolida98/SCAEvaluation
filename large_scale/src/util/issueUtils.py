from ast import main
import os
import requests
import csv
import json

from util.versionUtil import check_in_range

tmp_cve_cache = {}


def get_issue_list(group_id, artifact_id, version):
    url = 'http://155.69.145.245:8090/issues'
    payload = f"""
        {{
            "name": "{artifact_id}",
            "vendor": "{group_id}",
            "version": "{version}",
            "platform": "maven"
        }}
    """
    header = {"Content-Type": "application/json", "charset": "UTF-8"}
    res = requests.post(url, headers=header, data=payload)
    # print(res.json())
    issue_list = []
    if res.status_code != 200:
        print(f" CVE list querying failed: {group_id}:{artifact_id}:{version}")
        return []
    else:
        content = res.json()
        if len(content) == 0:
            # print(f"{group_id}:{artifact_id}:{version} query cve is empty")
            return []
        for item in content:
            if item['libraryVersion']['libraryName'] != artifact_id or item['libraryVersion']['libraryVendor'] != group_id:
                continue
            if item['issue'].startswith('CVE') or item['issue'].startswith('CNVD'):
                issue_list.append(item['issue'])
    return issue_list

def get_issue_list_with_cache(gav, issue_cache_json):
    g, a, v = gav.split(':')
    if v.endswith('SNAPSHOT'):
        return []
    if gav in issue_cache_json:
        return issue_cache_json[gav]
    else:
        cve_list = get_issue_list(g, a, v)
        issue_cache_json[gav] = cve_list
        return cve_list

def get_issue_list_with_git_advisory(gav, issue_cache_json):
    tmp_gav = gav.split(':')
    if len(tmp_gav) != 3:
        print('WARNING | ', tmp_gav)
        return []
    g,a,v = tmp_gav[0], tmp_gav[1], tmp_gav[2]
    ga = f'{g}:{a}'
    gav = f'{g}:{a}:{v}'
    if v.endswith('SNAPSHOT'):
        return []
    if gav not in tmp_cve_cache:
        if ga in issue_cache_json:
            vr_list = issue_cache_json[ga]
            cve_list = []
            for vr in vr_list:
                range = vr['version_range']
                cve = vr['cve']
                if check_in_range([v.strip()], range):
                    cve_list.append(cve)
            tmp_cve_cache[gav] = cve_list
            return cve_list
        else:
            return []
    else:
        print('hit cache, sise:', len(tmp_cve_cache))
        return tmp_cve_cache[gav]
    


if __name__ == '__main__':
    for i in range(10):
        print(get_issue_list('org.apache.logging.log4j','log4j-core','2.11.1'))
