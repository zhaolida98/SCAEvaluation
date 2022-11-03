import requests

def check_in_range(versionlist, range, session=None):
    semver_host = '155.69.151.221'
    semver_port = '8091'
    ret = []
    with requests.Session() as session:
        for version in versionlist:
            res = session.get(f'http://{semver_host}:{semver_port}/checkinrange?version={version}&range={range}'\
                .replace(' ', '%20').replace('[', '%5B').replace(']', '%5D'))
            res.raise_for_status()
            session.close()
            if res.content.decode() == 'true':
                ret.append(version)
    return ret


if __name__ == '__main__':
    print(check_in_range(['1.0.0', '2.0.0', '0.0.7',' 3.0.0', '3.2.5'], '[3.2.5]') == True)
    if check_in_range(['1.0.0', '2.0.0', '0.0.7',' 3.0.0', '3.2.5'], '[3.2.4]'):
        print('true')