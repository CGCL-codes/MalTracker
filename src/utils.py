import csv
import numpy as np
import os
from tree_sitter import Language, Parser
from scipy.stats import entropy
import validators
from pathvalidate import is_valid_filepath
import esprima
import re
import shutil
import logging
import sys
import concurrent.futures

logging.basicConfig(filename='./log/utils.log', level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_csv(file_path, has_header=False, convert_func=int):
    """return content and the header of the csv file"""
    header = []
    content = []
    with open(file_path) as f:
        csv_reader = csv.reader(f, delimiter=',')
        if has_header:
            header = next(csv_reader, None)
        for row in csv_reader:
            content.append([convert_func(i) for i in row])
    return content, header

def write_csv(file_path, content, header=None):
    with open(file_path, "a") as csvfile:
        spamwriter = csv.writer(csvfile)
        spamwriter.writerow(content)


def get_strings(file_path):
    """get string from each file"""
    JS_LANGUAGE = Language('../res/build/my-languages.so', 'javascript')
    parser = Parser()
    parser.set_language(JS_LANGUAGE)
    tree = parser.parse(open(file_path, "rb").read())
    query = JS_LANGUAGE.query("""(string) @string""")
    try:
        captures = [i[0].text.decode("utf8") for i in query.captures(tree.root_node)]
    except UnicodeDecodeError:
        print([i[0].text for i in query.captures(tree.root_node)])
        return []
    return captures


def get_shannon_entropy(filename):
    """Calculate the Shannon entropy of the file"""
    data = np.fromfile(filename, dtype=np.uint8)
    _, counts = np.unique(data, return_counts=True)
    prob = counts / len(data)
    return entropy(prob)


def get_all_files_from_pkg(pkg_path):
    all_file_list = []
    for dirpath, dirnames, filenames in os.walk(pkg_path):
        for filename in filenames:
            if "node_modules" in dirpath:
                break
            file_path = os.path.join(dirpath, filename)
            all_file_list.append(file_path)
    return all_file_list
    

def get_sensitive_API():
    file_path = "../res/sensitiveFunc.txt"
    with open(file_path) as f:
        sensitive_func = [i.strip() for i in f.readlines()]
    return sensitive_func
        

def map_func(node):
    return False
    

def get_structure_feature(file_path, node_location):
    # print(file_path, node_location)
    js_func_map = {
        "loop": ["for_in_statement", "for_of_statement", "for_statement", "while_statement", "do_while_statement"],
        "exception": ["try_statement", "throw_statement"],
        "condition": ["if_statement", "switch_statement"],
        "assignment": ["assignment_expression", "variable_declarator", "call_expression", "binary_expression"],
        "return": ["return_statement"],
    }
    JS_LANGUAGE = Language('../res/build/my-languages.so', 'javascript')
    parser = Parser()
    parser.set_language(JS_LANGUAGE)
    with open(file_path, "rb") as f:
        tree = parser.parse(f.read())

    target_cursor = get_callsite(tree, map_ast_location(node_location))
    parent_type_list= get_type_list(tree, target_cursor)
    target_cursor = get_callsite(tree, map_ast_location(node_location))
    argument_list = get_string_argument(target_cursor)

    feature_dict = {}
    for argument in argument_list:
        feature_dict.setdefault("has_domain", bool(validators.domain(argument)))
        feature_dict.setdefault("has_url", bool(validators.url(argument)))
        feature_dict.setdefault("has_ip", bool(validators.ipv4(argument)) or bool(validators.ipv6(argument)))
        feature_dict.setdefault("has_file_path", (is_valid_filepath(argument) or argument.startswith("/")))

    # print(parent_type_list)
    for key, value in js_func_map.items():
        feature_dict.setdefault(key, 0)
        for parent_type in parent_type_list:
            if parent_type in value:
                feature_dict.setdefault(key, 1)
    return feature_dict


def map_ast_location(location):
    location = tuple([i-1 for i in location[1:]])
    return (location[0:2], location[2:])


def get_string_argument(cursor):
    current_cursor_id = cursor.node.id

    string_argument = []
    reached = False
    while reached == False:
        if cursor.node.type == "string_fragment":
            string_argument.append(cursor.node.text.decode("utf8"))
        if cursor.goto_first_child():
            continue
        if cursor.goto_next_sibling():
            continue
        retracing = True
        while retracing:
            cursor.goto_parent()           
            if cursor.node.id == current_cursor_id:
                retracing = False
                reached = True
            if cursor.goto_next_sibling():
                retracing = False
    return string_argument


def get_type_list(tree, cursor):
    if cursor is None:
        return []    
    node_feature = []
    while cursor.node != tree.root_node:
        cursor.goto_parent()
        node_feature.append(cursor.node.type)
    return node_feature


def get_callsite(tree, location):
    cursor = tree.walk()
    reached_root = False
    while reached_root == False:
        if (cursor.node.start_point, cursor.node.end_point) == location:
            return cursor
        if cursor.goto_first_child():
            continue
        if cursor.goto_next_sibling():
            continue
        retracing = True
        while retracing:
            if not cursor.goto_parent():
                retracing = False
                reached_root = True
            if cursor.goto_next_sibling():
                retracing = False
        return None

def get_func_type(func_type):
    return "SINK" if func_type.startswith("SINK") else "SOURCE"


from typing import List, TypeVar, Callable

T = TypeVar('T')
def first_index_of(array: List[T], cond_fn: Callable[[T], bool]) -> int or None:
    for i, item in enumerate(array):
        if cond_fn(item):
            return i
    return None


def last_line_col(filepath: str) -> tuple[int, int]:
    with open(filepath, 'r') as f:
        line_count = 0
        col_count = 0
        lines = f.readlines()
        for line in lines:
            line_count += 1
            col_count = len(line)
        if len(lines) == 0:
            return 0, 0
        if lines[-1].endswith('\n'):
            return line_count + 1, 1
        return line_count, col_count + 1

def read_code(file_path, loc):
    if -1 in loc:
        with open(file_path, "r") as f:
            function_content = f.read()
    else:
        with open(file_path, "r") as f:
            begin_line, begin_col, end_line, end_col = loc[1:]
            lines = f.readlines()
            if end_line == begin_line:
                function_content = lines[begin_line-1][begin_col-1:end_col-1]
            else:
                relevant_lines = lines[begin_line-1:end_line]
                relevant_lines[0] = relevant_lines[0][begin_col-1:]
                relevant_lines[-1] = relevant_lines[-1][:end_col-1]
                function_content = "".join(relevant_lines)
    return function_content
    return function_content[function_content.find("{")+1:function_content.rfind("}")]

def remove_if_existing(list, element):
    if element in list:
        list.remove(element)

def add_if_not_existing(list, element):
    if element not in list:
        list.append(element)

def get_sensitive_list():
    with open('../res/sensitiveFunc.txt') as f:
        sensitive_list = f.read().splitlines()
    return sensitive_list

def get_sensitive_map():
    with open('../res/sensitiveFunc.txt') as f:
        sensitive_list = f.read().splitlines()
    sensitive_map = {sensitive_list[i]: i for i in range(len(sensitive_list))}
    return sensitive_map

def get_name_for_call(node):
    """ get the name of the method call node """
    assert node['type'] in ('AST_CALL', 'AST_METHOD_CALL')
    return node['code'].split('(')[0]

def is_sensitive(node):
    # function_name = get_name_for_call(node)
    # method_name = function_name.split('.')[-1].split(' ')[-1]
    sensitive_list = get_sensitive_list()
    if node['real_name'] in sensitive_list:
        return True
    return False

def extract_strings(js_code):
    try:
        tokens = esprima.tokenize(js_code)
    except Exception as e:
        print(e, file=open('../error.log', 'a'))
        return []
    strings = [tokens[i].value for i in range(len(tokens)) if tokens[i].type == 'String' and tokens[i-2].value in ('eval', 'exec')]
    return strings

def get_all_strings():
    target_dir_path = '../tmp/first_tmp/js_f'
    coped_list = []
    output_file = open('../res/PKGString.csv', 'w')
    for file_name in os.listdir(target_dir_path):
        file_path = os.path.join(target_dir_path, file_name)
        pkg_name = file_name.split('@')[0]
        with open(file_path, 'r') as f:
            js_code = f.read()
        extracted_strings = extract_strings(js_code)
        for string in extracted_strings:
            output = (pkg_name, string)
            if output not in coped_list:
                coped_list.append(output)
                if len(string) > 10 and ('exec' in js_code or 'eval' in js_code):
                    print(pkg_name, string, file=output_file)
    output_file.close()

def extra_functionid(summary):
    if 'File entry' in summary:
        return summary
    function_re = r'function\s+(\w+)\s*\('
    try:
        function_id = re.findall(function_re, summary)[0]
    except:
        # print('------------------')
        # print(summary)
        return None
    return function_id

def get_sensitive_type(sensitive_id):
    type_map = get_sensitive_type_map()
    return next((i for i in range(len(type_map)) if type_map[i][0] <= sensitive_id <= type_map[i][1]), None)

def get_sensitive_type_map():
    return [
        (1, 106),
        (107, 220),
        (221, 274),
        (275, 382),
        (383, 402)
    ]

def extract_mockfunc_name(summary):
    return summary[summary.find(' ')+1:summary.find('(')]

def extract_mockfunc_lib(filepath):
    return filepath.split('/')[-1].split('.')[0]

def extract_name(path):
    return list(set([snippet_id[:snippet_id.find('@')] for snippet_id in os.listdir(path)]))

def get_output_count():
    print('malicious package:', len(extract_name('../snippets/malware')), len(os.listdir('../snippets/malware')), len(os.listdir('../../data/malware/test')))
    print('new package:', len(extract_name('../snippets/new')), len(os.listdir('../snippets/new')), len(os.listdir('../../data/new')))
    print('benign package:', len(extract_name('../snippets/benign')), len(os.listdir('../snippets/benign')), len(os.listdir('../../data/benign')))

def remove_node_modules(node_path):
    shutil.rmtree(node_path)

def remove_multi():
    target_paths = ['../../data/new/', '../../data/benign/', '../../data/malware/test/']
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        for target_path in target_paths:
            for pkg_name in os.listdir(target_path):
                base_path = os.path.join(target_path, pkg_name)
                if os.path.isfile(base_path):
                    continue
                for i in os.listdir(base_path):
                    if 'DS_Store' in i:
                        os.remove(os.path.join(base_path, i))
                if len(os.listdir(base_path)) == 1:
                    base_path += '/' + 'package' + '/'
                if not os.path.exists(base_path) or 'node_modules' not in os.listdir(base_path):
                    continue
                logger.info(base_path)
                node_path = os.path.join(base_path, 'node_modules')
                future = executor.submit(remove_node_modules, node_path)

if __name__ == "__main__":
    get_output_count()
    