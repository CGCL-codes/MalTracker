import os

def compare_backup():
    backup = [i for i in os.listdir('../PDGFeature/malware_bk') if i not in os.listdir('../PDGFeature/malware')]
    for i in backup:
        print(f"../PDGFeature/malware_bk/{i}")


def get_pkg_count(target_dir_path):
    pkg_ids = list(set([i[:i.find('@')] for i in os.listdir(target_dir_path)]))
    for i in pkg_ids:
        print(i)
    print(len(pkg_ids))

def remove_unused_baseline_features():
    tool_feature_path = '../PDGFeature/malware_bk'
    baseline_path = '../baseline/BaselineFeature/malware_bk/'
    target_path = '../baseline/BaselineFeature/malware'
    tools_files = list(set([i[:i.find('@')] for i in os.listdir(tool_feature_path)]))
    for file_name in os.listdir(baseline_path):
        if file_name in tools_files:
            os.system(f"cp {baseline_path}/{file_name} {target_path}")

def filter_snippet(input_list, coped):
    results = []
    for i in input_list:
        j = i
        if "@@" in i:
            j = i[:i.find('@@')]
        if j in coped:
            continue
        results.append(j)
    return results

def extract_llm():
    with open('../newpkgs/coped.txt') as f:
        coped = [i.strip() for i in f.readlines()]
    with open('../newpkgs/before_review.txt') as f:
        pkgs_llm = filter_snippet([i.strip() for i in f.readlines()], coped)
    with open('../newpkgs/results.txt') as f:
        pkgs_without = [i.strip() for i in f.readlines()]
    with open('../newpkgs/toReview.txt', 'w') as f:
        for i in pkgs_llm:
            print(f"{i}", file=f)
            print(f"./tmp/pdg/fast/{i}")

def get_sensitive_functions(target_dir_path):
    counter = 0
    c = 0
    for file_name in os.listdir(target_dir_path):
        with open(f"{target_dir_path}/{file_name}") as f:
            if f.read().count('///') > 1:
                counter += 1
        c += 1
        print(c, counter)
    print(counter)
