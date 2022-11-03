import json, os
import os
import multiprocessing
repos_string = '/home/lida/.m2'
gav_json = '/home/lyuye/maven_ga_sv.json'
def collect(group_id, artifact_id, version_name):
    os.system(f'mvn org.apache.maven.plugins:maven-dependency-plugin:2.8:get \
                                            -DgroupId={group_id} \
                                            -DartifactId={artifact_id} \
                                            -Dversion={version_name} \
                                            -Dtransitive=false \
                                            -DremoteRepositories={repos_string} \
                                            -Dpackaging=pom')


if __name__ == '__main__':
    content = json.load(open(gav_json, 'r'))
    try:
        pool = multiprocessing.Pool(31)
        for idx, ga in enumerate(content.keys()):
            print(f'\rprocessing {idx}/ {len(content)}')
            tmp = ga.split('|')
            g, a = tmp[0], tmp [1]
            for v in content[ga]:
                pool.apply_async(func=collect, args=(g, a, v, ))
    except Exception as e:
        print(e)
    finally:
        pool.close()
        pool.join()
