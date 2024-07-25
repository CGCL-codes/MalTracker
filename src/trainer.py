import ast
import random
from sklearn.metrics import classification_report
from sklearn.metrics import precision_recall_fscore_support

from sklearn import tree, svm
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
clf = RandomForestClassifier()
import os
from tqdm import tqdm
import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def clf_chooser():
    # clf = svm.SVC(kernel='rbf')
    # clf = KNeighborsClassifier(n_neighbors=5)
    clf = tree.DecisionTreeClassifier(criterion='gini')
    # clf = RandomForestClassifier()
    return clf

def find_key_from_dict(dict, value):
    keys = []
    for k, v in dict.items():
        if v[0] == value:
            keys.append(k)
    return keys

def remove_du(input_list):
    output_list = []
    for i in input_list:
        if i not in output_list:
            output_list.append(i)
    return output_list

def baseline_filter_no_sensitive(features):
    return 0

def filter_no_sensitive(feature):
    return sum(feature[6:409]) == 0

def slice_dict(input_dict, key_list, ratio):
    len_list = [len(input_dict[i]) for i in key_list]
    total_len = sum(len_list)
    slice = next((i for i in range(len(key_list)) if sum(len_list[:i]) > ratio*total_len), None)
    return slice, sum(len_list[:slice])

def get_feature(feature_path, tmp_feature_file_path, filter, is_pkg=True):
    features = {}
    if tmp_feature_file_path is not None:
        with open(tmp_feature_file_path) as f:
            content = f.read()
        if len(content):
            features = ast.literal_eval(content)
            return features
    for file_name in tqdm(os.listdir(feature_path)):
        file_path = os.path.join(feature_path, file_name)
        with open(file_path) as f:
            content = f.read()
        try:
            if is_pkg:
                pkg_id = file_name[:file_name.find('@')]
            else: pkg_id = file_name
            feature = ast.literal_eval(content[content.find('['):])
            if filter(feature):
                continue
            if pkg_id not in features:
                features.setdefault(pkg_id, [feature])
            else:
                features.get(pkg_id).append(feature)
        except SyntaxError:
            logging.error(f"SyntaxError: {file_path}")
            continue
    if tmp_feature_file_path is not None:
        with open(tmp_feature_file_path, 'w') as f:
            print(features, file=f)
    return features

def evaluate_oracle_instance(benign_feature_path, mal_feature_path, filter, benign_storage_path=None, malware_storage_path=None):
    logging.info('getting benign features...')
    benign_features = [i for j in get_feature(benign_feature_path, None, filter, is_pkg=False).values() for i in j]
    # benign_features = filter(benign_features)
    
    logging.info('getting malicious features...')
    mal_feature_dict = get_feature(mal_feature_path, None, filter, is_pkg=False)
    mal_features = [i for j in mal_feature_dict.values() for i in j]
    # mal_features = filter(mal_features)
    llm_feature_dict = get_feature('../PDGFeature/LLM', None, filter, is_pkg=False)
    llm_features = [i for j in llm_feature_dict.values() for i in j]

    # mal_features.extend(llm_features)
    mal_features = remove_du(mal_features)
    benign_features = remove_du(benign_features)

    benign_len = len(benign_features)
    mal_len = len(mal_features)
    logging.info('evaluating...')
    logging.info(f"counts of benign instances {benign_len}")
    logging.info(f"counts of malicious instances {mal_len}")
    ratio = 0.9
    benign_train_len = int(benign_len * ratio)
    mal_train_len = int(mal_len * ratio)
    random.shuffle(benign_features)
    random.shuffle(mal_features)
    train_set = benign_features[:benign_train_len] + mal_features[:mal_train_len]
    test_set = benign_features[benign_train_len:] + mal_features[mal_train_len:]
    test_proof = [1]*(benign_len-benign_train_len) + [2]*(mal_len-mal_train_len)
    train_proof = [1]*benign_train_len + [2]*mal_train_len

    clf = clf_chooser()
    logging.info("training...")
    m = clf.fit(train_set, train_proof)

    logging.info("predicting...")
    pre_res = m.predict(test_set)

    # print("results of `precision_recall_fscore_support`:")
    # precision, recall, f1_score, support = precision_recall_fscore_support(test_proof, pre_res)

    # print("Precision:", precision)
    # print("Recall:", recall)
    # print("F1 Score:", f1_score)
    # print("Support:", support)

    print("\nresults of `classification_report`:")
    print(classification_report(test_proof, pre_res, digits=3))
    # return classification_report(test_proof, pre_res, digits=3)

    # capture wrong labeled malicious code
    # mal_ids = []
    # mal_list = [i for i in range(len(pre_res)) if pre_res[i] == 1 and i > benign_len-benign_train_len]
    # print(mal_list)

    # for i in mal_list:
    #     mal_ids.extend(find_key_from_dict(mal_feature_dict, test_set[i]))
    # for i in mal_ids:
    #     print(f"../snippets/malware/{i}")
    # return mal_ids


def evaluate_oracle_package(benign_feature_path, mal_feature_path, benign_storage_path=None, malware_storage_path=None):
    # FIXME:
    logging.info('getting benign features...')
    benign_features = get_feature(benign_feature_path, benign_storage_path, filter_no_sensitive)
    benign_pkg_ids = list(benign_features.keys())
    benign_pkgs_len = len(benign_features)

    logging.info('getting malicious features...')
    mal_features = get_feature(mal_feature_path, malware_storage_path, filter_no_sensitive)
    mal_pkg_ids = list(mal_features.keys())
    mal_pkgs_len = len(mal_features)

    # benign_features_len = len(benign_features)
    # mal_features_len = len(mal_features)

    logging.info('evaluating...')
    logging.info(f"counts of benign instances {benign_pkgs_len}")
    logging.info(f"counts of malicious instances {mal_pkgs_len}")
    ratio = 0.8

    random.shuffle(benign_pkg_ids)
    random.shuffle(mal_pkg_ids)

    # benign_slice: length of packages
    # benign_len: length of features
    benign_slice, benign_len = slice_dict(benign_features, benign_pkg_ids, ratio)
    mal_slice, mal_len = slice_dict(mal_features, mal_pkg_ids, ratio)

    train_proof = [1]*benign_len + [2]*mal_len
    train_set = [j for i in benign_pkg_ids[:benign_slice] for j in benign_features[i]] + [j for i in mal_pkg_ids[:mal_slice] for j in mal_features[i]]
    test_set = [j for i in benign_pkg_ids[benign_slice:] for j in benign_features[i]] + [j for i in mal_pkg_ids[mal_slice:] for j in mal_features[i]]
    
    test_proof = [1]*(benign_pkgs_len-benign_slice) + [2]*(mal_pkgs_len-mal_slice)

    clf = clf_chooser()
    logging.info("training...")
    m = clf.fit(train_set, train_proof)

    logging.info("predicting...")
    pre_res = m.predict(test_set)

    predict_result = []
    current_idx = 0
    for pkg in benign_pkg_ids[benign_slice:]:
        current_len = len(benign_features[pkg])
        predict_result.append(max(pre_res[current_idx:current_idx+current_len]))
        current_idx += current_len
    # current_idx = 0
    for pkg in mal_pkg_ids[mal_slice:]:
        current_len = len(mal_features[pkg])
        predict_result.append(max(pre_res[current_idx:current_idx+current_len]))
        current_idx += current_len

    print("\nresults of `classification_report`:")
    print(classification_report(test_proof, predict_result, digits=3))

def predict_new_pkg(benign_feature_path, mal_feature_path, new_feature_path, filter, output_path, LLM_feature_path=None):
    logging.info('getting benign features...')
    benign_features = [i for j in get_feature(benign_feature_path, None, filter, is_pkg=False).values() for i in j]
    print(benign_features)
    logging.info('getting malicious features...')
    mal_features = [i for j in get_feature(mal_feature_path, None, filter, is_pkg=False).values() for i in j]

    if LLM_feature_path:
        logging.info('getting LLM features...')
        LLM_features = [i for j in get_feature(LLM_feature_path, None, filter, is_pkg=False).values() for i in j]
        mal_features.extend(LLM_features)
        
    logging.info('getting new features')
    new_features_dict = get_feature(new_feature_path, None, filter, is_pkg=False)
    new_features = [i for j in new_features_dict.values() for i in j]
    print(len(new_features))

    new_len = len(new_features)
    benign_len = len(benign_features)
    mal_len = len(mal_features)

    logging.info('evaluating...')
    train_proof = [1]*benign_len + [2]*mal_len
    train_set = benign_features + mal_features
    clf = clf_chooser()
    logging.info("training...")
    m = clf.fit(train_set, train_proof)
    
    logging.info("predicting new packages...")
    predict_res = m.predict(new_features)

    mal_list = [i for i in range(len(predict_res)) if predict_res[i] == 2]
    print(mal_list)
    print(len(mal_list))
    mal_ids = []
    for i in mal_list:
        mal_ids.extend(find_key_from_dict(new_features_dict, new_features[i]))
    # mal_ids = [find_key_from_dict(new_features_dict, list(mal_list)[i]) for i in mal_list]
    mal_ids = list(set([i[:i.find('@')] for i in mal_ids]))
    print(len(mal_ids))
    with open(output_path, 'a') as f:
        for i in mal_ids:
            print(i, file=f)
    refine_new_pkgs(output_path)
    return mal_ids

def refine_new_pkgs(output_path):
    with open(output_path) as f:
        lines = list(set([i.strip() for i in f.readlines()]))
    with open(output_path, 'w') as f:
        for line in lines:
            print(line, file=f)

def evaluate_llm(benign_feature_path, mal_feature_path, new_feature_path, LLM_feature_path):
    results_with_llm = predict_new_pkg(benign_feature_path, mal_feature_path, new_feature_path, filter_no_sensitive, LLM_feature_path)
    results_without = predict_new_pkg(benign_feature_path, mal_feature_path, new_feature_path, filter_no_sensitive)

    # results_path_llm = [f"./tmp/pdg/fast/{i}" for i in results_with_llm]
    # results_path_without = [f"./tmp/pdg/fast{i}" for i in results_without]
    for i in results_with_llm:
        if i not in results_without:
            print(f"./tmp/pdg/fast/{i}")

    with open('../newpkgs/before_review.txt') as f:
        stored_pkgs = [i.strip() for i in f.readlines()]
        results = [i for i in results_with_llm if i not in stored_pkgs]
    with open('../newpkgs/before_review.txt', 'a') as f:
        for i in results:
            print(i, file=f)

    # with open('../newpkgs/results.txt') as f:
    #     stored_pkgs = [i.strip() for i in f.readlines()]
    #     results = [i for i in results_without if i not in stored_pkgs]
    # with open('../newpkgs/results.txt', 'a') as f:
    #     for i in results:
    #         print(i, file=f)

def evaluate_our_tool():
    benign_feature_path = '../PDGFeature/benign'
    benign_feature_path_without_callers = '../PDGFeature/benign_without_callers'
    benign_feature_path_without_gd = '../PDGFeature/benign_without_gd'

    mal_feature_path = '../PDGFeature/malware'
    mal_feature_path_without_callers = '../PDGFeature/malware_without_callers'
    LLM_feature_path = '../PDGFeature/LLM'
    new_feature_path = '../PDGFeature/new'

    evaluate_oracle_instance(benign_feature_path, mal_feature_path, filter_no_sensitive, '../PDGFeature/BenignFeatureIns.txt', '../PDGFeature/MalwareFeatureIns.txt')


def evaluate_baseline():
    benign_feature_path = '../baseline/BaselineFeature/benign_bk'
    new_feature_path = '../baseline/BaselineFeature/new'
    mal_feature_path = '../baseline/BaselineFeature/malware'
    evaluate_oracle_package(benign_feature_path, mal_feature_path)


if __name__ == '__main__':
    benign_feature_path = '../PDGFeature/benign'
    mal_feature_path = '../PDGFeature/malware'
    LLM_feature_path = '../PDGFeature/LLM'
    new_feature_path = '../PDGFeature/new'
    # result = evaluate_our_tool()
    # for i in range(10):
    # predict_new_pkg(benign_feature_path, mal_feature_path, new_feature_path, filter_no_sensitive, '../newpkgs/newpkgs.txt')


    new_input_pkg_path = '../../data/new'
    new_output_pkg_path = '../baseline/BaselineFeature/new'

    mal_input_pkg_path = '../../data/malware/test'
    mal_output_pkg_path = '../baseline/BaselineFeature/malware'

    benign_input_pkg_path = '../../data/benign'
    benign_output_pkg_path = '../baseline/BaselineFeature/benign'
    predict_new_pkg(benign_output_pkg_path, mal_output_pkg_path, new_output_pkg_path, baseline_filter_no_sensitive, '../baseline/newpkg.txt')
