import os
import requests
import csv
import json


def get_issue_list(group_id, artifact_id, version):
    url = 'http://94.74.83.184:8086/issues'
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
    if gav in issue_cache_json:
        return issue_cache_json[gav]
    else:
        cve_list = get_issue_list(g, a, v)
        issue_cache_json[gav] = cve_list
        return cve_list