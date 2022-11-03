import pymongo
import os
import csv
import subprocess
import concurrent.futures
client = pymongo.MongoClient("155.69.147.134", port=27018)
github = client['github']
col = github['github_100_stars2']

full_ids = []
with open("../manifest/collection.csv", "r") as f:
    reader = csv.reader(f)
    c = -1
    for line in reader:
        c += 1
        if c == 0:
            continue
        full_ids.append(line[0])

full_ids = list(set(full_ids))


def process(id, root_path):
    pomfiles = {}
    for root,dirs,files in os.walk(root_path):  # 遍历file_path下所有的子目录及文件
        for file in files:  #遍历当前路径下所有非目录子文件
            if file == 'pom.xml':
                with open(os.path.join(root, file), encoding="utf-8") as f:
                    # 设置以utf-8解码模式读取文件，encoding参数必须设置，否则默认以gbk模式读取文件，当文件中包含中文时，会报错
                    content = f.read()
                    pomfiles[root + "/" + file] = content
    col.insert({'id': id, 'poms': pomfiles}, check_keys=False)

def proceaa2(id, root_path):
    if col.find_one({"id": id}):
        return
    if not os.path.exists(root_path):
        return
    file_paths = []
    pomfiles = {}
    os.chdir(root_path)
    p = subprocess.Popen('git ls-files | grep pom.xml', shell=True, stdout=subprocess.PIPE)
    out, err = p.communicate()
    for line in out.splitlines():
        file_paths.append(line.decode("UTF-8"))
    for x in file_paths:
        # print(root_path, x)
        pomfiles[root_path + "/" + x] = ""
        if os.path.exists(os.path.join(root_path, x)):
            with open(os.path.join(root_path, x), encoding="utf-8") as f:
                # 设置以utf-8解码模式读取文件，encoding参数必须设置，否则默认以gbk模式读取文件，当文件中包含中文时，会报错
                content = f.read()
                pomfiles[root_path + "/" + x] = content
    return {'id': id, 'poms': pomfiles}

# count = 0
# for key, value in full_ids.items():
#     count += 1
#     print(str(count) + ":" + key)
#     proceaa2(key, value)

# process('apache/hadoop', '/home/chengwei/data/github_most_stars/projects/apache/hadoop')

def multiprocess(skip, limit):
    client1 = pymongo.MongoClient("155.69.147.134", port=27018)
    github1 = client1['github']
    col1 = github1['github_100_stars2']
    this_keys = full_ids[skip: skip + limit]
    count = 0
    for k in this_keys:
        count += 1
        pomfiles = proceaa2(k, "/home/lida/SCAEvaluation-main/large_scale/projects/" + k.replace("/", "@"))
        if pomfiles:
            col1.insert(pomfiles, check_keys=False)
        else:
            if not col.find_one({"id": k}):
                print("error happen in: " + k)
        # print(str(count + skip) + ":" + k)

with concurrent.futures.ProcessPoolExecutor(max_workers=12) as executor:
    futures = [executor.submit(multiprocess, i, 100) for i in range(0, int(len(full_ids)), 100)]