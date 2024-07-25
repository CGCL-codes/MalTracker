import os
import sys
import re
from callgraph import Callgraph
from iggraph import IGGraph
from utils import read_code
from spt2pdg import PDG
import concurrent.futures
from utils import extra_functionid
import shutil

from utils import extract_mockfunc_lib

"""
1. get meta features of a pkg
2. get call graph of the pkg
3. locate the invocation chain of the sensitive function
4. locate the callsites of the chain and get the features of the callsites (PDG first)
"""

class Extractor:
    """ extract features of one pkg """
    def __init__(self, base_path, cg_json):
        self.pkg_id = base_path[base_path.rfind('/')+1:]
        self.base_path = base_path
        for i in os.listdir(self.base_path):
            if 'DS_Store' in i:
                os.remove(os.path.join(self.base_path, i))
        if len(os.listdir(self.base_path)) == 1:
            self.base_path += '/' + os.listdir(self.base_path)[0] + '/'
        print(self.base_path)
        if 'node_modules' not in os.listdir(self.base_path):
            self.npm_install()
        self.cg_json = cg_json
        self.execute_jelly()
        self.callgraph = Callgraph(self.base_path, self.cg_json)
        self.graph = IGGraph(self.callgraph)

    def npm_install(self):
        os.popen(f"cd {self.base_path} && npm install --ignore-scripts --no-audit --production --registry https://registry.npm.taobao.org/ && cd -").read()

    def execute_jelly(self):
        command = (f"ts-node ../res/jelly/src/main.ts --timeout 15 --callgraph-json {self.cg_json} {self.base_path}")
        # print(command)
        # os.system(command)
        os.popen(command).read()

    def remove_node_modules(self):
        if 'node_modules' in os.listdir(self.base_path):
            shutil.rmtree(os.path.join(self.base_path, 'node_modules'))

    def output_pdg(self, output_path):
        tmp_output_path = os.path.join(output_path, self.pkg_id)
        coped_idx = []
        counter = 0
        for idx, v in self.graph.sensitive_relationship.items():               
            current_func = self.graph.callgraph.functions[idx]
            current_filepath = current_func.filepath
            if idx in coped_idx or 'mock' in current_filepath or 'node_modules' in current_filepath:
                continue
            with open(tmp_output_path+f"@{counter}.js", 'w') as f:
                for i in v:
                    # get builtin functions
                    directed_callee = self.graph.callgraph.functions[i]
                    start_node = self.graph.ig_graph.vs.select(idx=i)[0]

                    callers = [self.graph.callgraph.functions[self.graph.ig_graph.vs[i]['idx']] for i in self.graph.ig_graph.subcomponent(start_node, mode="out")]
                    # for i in callers:
                    #     print(i.filepath, i.summary)
                    try:
                        builtin_callees = ['.'.join([extract_mockfunc_lib(i.filepath), extra_functionid(i.summary)]) for i in callers if i.get_sensitive_info()]
                    except TypeError:
                        continue
                    # print(builtin_callees)
                    print(f"/// {extra_functionid(directed_callee.summary)}: {builtin_callees}", file=f)
                print('/// end', file=f)
                print(read_code(current_func.filepath, current_func.def_site), file=f)
                coped_idx.append(idx)
            counter += 1
            # pdg = PDG(tmp_output_path)
            # pdg.output_graph()

def extract(pkg_path, output_path, tmp_file=None):
    if tmp_file is None:
        tmp_file = os.path.join('./tmp/cg/json/', pkg_path[pkg_path.rfind('/')+1:]+'.json')
    extr = Extractor(pkg_path, tmp_file)
    with open('./tmp/cg/CopedPackage.txt', 'a') as f:
        print(pkg_path, file=f)
    extr.output_pdg(output_path)
    extr.remove_node_modules()

def extract_all_cg_snippets(input_path, output_path):
    with open('./tmp/cg/CopedPackage.txt') as f:
        coped_pkgs = f.read().split('\n')
    coped_pkgs.extend(list(set([os.path.join(input_path, snippet_id[:snippet_id.find('@')]) for snippet_id in os.listdir(output_path)])))
    with concurrent.futures.ProcessPoolExecutor(max_workers=64) as executor:
        for pkg_name in os.listdir(input_path):
            pkg_path = os.path.join(input_path, pkg_name)
            if pkg_path in coped_pkgs:
                continue
            try:
                future = executor.submit(extract, pkg_path, output_path)
            except KeyboardInterrupt as e:
                sys.exit() 

def extract_all_single_process(input_path, output_path):
    for pkg_name in os.listdir(input_path):
        pkg_path = os.path.join(input_path, pkg_name)
        extract(pkg_path, output_path)

if __name__ == '__main__':
    new_input_pkg_path = '../../data/new'
    new_output_pkg_path = '../snippets/new'

    mal_input_pkg_path = '../../data/malware/test'
    mal_output_pkg_path = '../snippets/malware'

    benign_input_pkg_path = '../../data/benign'
    benign_output_pkg_path = '../snippets/benign'
    coped_pkgs = list(set([snippet_id[:snippet_id.find('@')] for snippet_id in os.listdir(benign_output_pkg_path)]))
    # print([i for i in os.listdir(benign_input_pkg_path) if i in coped_pkgs])

    # extract_all_single_process(mal_input_pkg_path, mal_output_pkg_path)
    extract_all_cg_snippets(new_input_pkg_path, new_output_pkg_path)
    # extract_all_cg_snippets(mal_input_pkg_path, mal_output_pkg_path)
    extract_all_cg_snippets(benign_input_pkg_path, benign_output_pkg_path)


    # extract('../../data/malware/test/a-function-99.10.9/', './testJelly')