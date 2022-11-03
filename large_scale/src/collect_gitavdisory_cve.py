import csv, json, os


cve2gav_cache = '/home/lida/SCAEvaluation-main/large_scale/cache/gitcve2gav.json'
gav2cve_cache = '/home/lida/SCAEvaluation-main/large_scale/cache/gitgav2cve.json'
advisory_repo_path = '/home/lida/Downloads/advisory-database/advisories/github-reviewed'
cve2gav = {}
gav2cve = {}


def parse_events2range(events: list):
    start = '('
    end = ')'
    if len(events) == 1:
        if 'introduced' in events[0]:
            start = f'[{events[0]["introduced"]}'
        if 'fixed' in events[0]:
            end = f'{events[0]["fixed"]}]'
    elif len(events) == 2:
        start = f'[{events[0]["introduced"]}'
        end = f'{events[1]["fixed"]}]'
    else:
        print("WARNING | unrecognized event type", events)
    return f'{start}, {end}'

def parse_advisory_json(json_path):
    with open(json_path, 'r') as f:
        content = json.load(f)
        related_cve = content['aliases']
        affected = content['affected']
        for a in affected:
            eco = a['package']['ecosystem']
            name = a['package']['name']
            if eco.lower() != 'maven':
                continue
            if 'ranges' in a:
                ranges = a['ranges']
                for r in ranges:
                    if r['type'] == 'ECOSYSTEM':
                        range = parse_events2range(r['events'])
                        if len(related_cve) > 1:
                            print(f'WARNING | multiple related cve in {json_path}')
                        for cve in related_cve:
                            if cve not in cve2gav:
                                cve2gav[cve] = []
                            if name not in gav2cve:
                                gav2cve[name] = []
                            cve2gav[cve].append({'ga': name, 'version_range': range})
                            gav2cve[name].append({'version_range':range, 'cve': cve})
            if 'version' in a:
                versions = a['versions']
                for v in versions:
                    cve2gav[cve].append({'ga': name, 'version_range': f'[{v}]'})
                    gav2cve[name].append({'version_range':f'[{v}]', 'cve': cve})

def run():
    # os.remove(cve2gav_cache)
    # os.remove(gav2cve_cache)
    # cve2gav = {}
    # gav2cve = {}
    try: 
        print(os.path.isdir(advisory_repo_path))
        for (root,dirs,files) in os.walk(advisory_repo_path, topdown=True):
            for f in files:
                if f.endswith(".json"):
                    json_path = os.path.join(root, f)
                    print('start processing', json_path)
                    parse_advisory_json(json_path)
    finally:
        with open(cve2gav_cache, 'w') as f:
            json.dump(cve2gav, f)
        with open(gav2cve_cache, 'w') as f:
            json.dump(gav2cve, f)


run()