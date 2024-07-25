import utils
from spt2pdg import PDG
import os
import concurrent.futures
import sys
from tqdm import tqdm
from func_timeout import func_set_timeout, FunctionTimedOut
import logging
import validators
from pathvalidate import is_valid_filepath
from pathvalidate import validate_filepath
import ast
import numpy as np
import networkx as nx
from node2vec import Node2Vec


logging.basicConfig(filename='./log/pkg2featureLLM.log', level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class FeatureExtractor:
    def __init__(self, pdg):
        self.target_stmts = ['AST_IF', 'AST_SWITCH', 'AST_FOR', 'AST_FOREACH', 'AST_WHILE', 'AST_TRY', 'AST_CATCH']
        self.pdg = pdg

    def load_sensitive_map(self):
        sensitive_call_map = {}
        self.sensitive_call_map = sensitive_call_map
        return 
        with open(self.pdg.file_path) as f:
            content = f.read()
            content = content[:content.find('/// end')]
            if not len(content):
                self.sensitive_call_map = sensitive_call_map
                return 0
            for item in content.strip().split('\n'):
                i = item[4:].split(': ')
                try:
                    sensitive_call_map[i[0]] = ast.literal_eval(i[1])[0]
                except IndexError:
                    continue
        self.sensitive_call_map = sensitive_call_map


    def load_calls(self):
        """ parse the method call node """
        self.total_calls = []
        self.sensitive_calls = []
        # print(self.pdg.nodes)
        self.load_sensitive_map()
        self.cope_method_name()
        for node in (i for i in self.pdg.nodes if i['type'] in ('AST_CALL', 'AST_METHOD_CALL')):
            # print(node)
            if node in self.total_calls:
                continue
            self.total_calls.append(node)
            # if (utils.is_sensitive(node) and node not in self.sensitive_calls) or 'JS_REQUIRE_BUILTIN' in self.pdg.find_ends_by_begin(node['id:ID'])[0]['flags:string[]']:
            if (utils.is_sensitive(node) and node not in self.sensitive_calls):
                self.sensitive_calls.append(node)
                # self.get_sensitive_structural_features(node)

                # parent_node = self.pdg.find_parent_pdg_node(node)
    # def cope_require_method(self):
    #     for node in self.pdg.nodes:
    #         if node['type'] == "AST_METHOD_CALL" and self.pdg.find_end_by_begin(node['id:ID']):
    #             self.sensitive_calls.append(node)

    def find_obj_name(self, node):
        while node['type'] != 'AST_VAR':
            node = self.pdg.find_ends_by_begin(node['id:ID'])[0]
        return self.pdg.find_ends_by_begin(node['id:ID'])[0]['code']

    def cope_method_name(self):
        for node in (i for i in self.pdg.nodes if i['type'] in ('AST_METHOD_CALL', 'AST_CALL')):
            node['real_name'] = utils.get_name_for_call(node)
            if node['real_name'] in self.sensitive_call_map:
                node['real_name'] = self.sensitive_call_map[node['real_name']]
        for node in (i for i in self.pdg.nodes if i['type'] == 'AST_METHOD_CALL'): 
            # print(node)
            if 'require(' not in node['code']:
                try:
                    obj_name = self.find_obj_name(node)
                except IndexError:
                    continue
                for i, v in self.pdg.require_map.items():
                    if obj_name == i:
                        node['real_name'] = utils.get_name_for_call(node).replace(i, v)
                        break
            elif self.pdg.find_node_by_idx(str(int(node['id:ID'])-1))['type'] != 'AST_METHOD_CALL':
                while self.pdg.find_ends_by_begin(node['id:ID'])[0]['type'] == 'AST_METHOD_CALL':
                    node = self.pdg.find_ends_by_begin(node['id:ID'])[0]
                try:
                    lib_name = self.pdg.find_ends_by_begin(self.pdg.find_ends_by_begin(self.pdg.find_ends_by_begin(node['id:ID'])[0]['id:ID'])[-1]['id:ID'])[0]['code']
                    method_name = next(i for i in self.pdg.find_ends_by_begin(node['id:ID']) if i['type'] == 'string')['code']
                except (IndexError, StopIteration) as e:
                    continue
                node['real_name'] = '.'.join([lib_name, method_name])

    def get_total_call_counts(self):        
        return len(list(set([i['code'] for i in self.total_calls])))

    def get_sensitive_call_counts(self):
        return len(list(set([i['code'] for i in self.sensitive_calls])))

    def get_global_structural_features(self):
        ''' structural features of the whole file '''
        self.loop_nodes = self.pdg.get_nodes_by_type(['AST_FOR', 'AST_WHILE', 'AST_FOREACH'])
        self.branch_nodes = self.pdg.get_nodes_by_type(['AST_IF', 'AST_SWITCH'])
        self.exception_nodes = self.pdg.get_nodes_by_type('AST_TRY')
        return {
            'loop_counts': len(self.loop_nodes), 
            'branch_counts': len(self.branch_nodes), 
            'exception_counts': len(self.exception_nodes)
        }

    def get_sensitive_structural_features(self, node):
        structures = []
        while True:
            if node['type'] in self.target_stmts:
                structures.append(node['type'])
            node = self.pdg.find_begin_by_end(node['id:ID'])
            if node is None:
                break
        return structures

    def get_string_arg(self, node):
        ''' return the string arg of the method call node '''
        ast_arg_node = next((i for i in self.pdg.find_ends_by_begin(node['id:ID']) if i['type'] == 'AST_ARG_LIST'), None)
        if ast_arg_node is None:
            return []
        strings = [child_node['code'] for child_node in self.pdg.find_ends_by_begin(ast_arg_node['id:ID']) if child_node['type'] == 'string']
        g = self.pdg.data_flow_graph
        if g is None or node['id:ID'] not in g.vs['name']:
            return strings
        for dataflow_node in g.subcomponent(g.vs.find(name=node['id:ID']), mode='in'):
            for i in self.pdg.find_ends_by_begin(g.vs[dataflow_node]['name']):
                if i['type'] == 'string':
                    strings.append(i['code'])
        return strings

    def get_dataflow_nodes(self, begin_node):
        ''' json.push() '''

        begin_parent_node = self.pdg.find_parent_pdg_node(begin_node)
        # end_parent_node = self.pdg.find_parent_pdg_node(end_node)
        g = self.pdg.data_flow_graph
        if g is None or begin_parent_node['id:ID'] not in g.vs['name']:
            return []
        reachable_nodes = [g.vs[i]['name'] for i in g.bfs(begin_parent_node['id:ID'])[0]]
        dataflow_nodes = [i for i in self.total_calls if self.pdg.find_parent_pdg_node(i) != None and self.pdg.find_parent_pdg_node(i)['id:ID'] in reachable_nodes]
        dataflow_nodes.remove(begin_node)
        return dataflow_nodes

    def get_nodes_in_group(self, nodes, group_ids):
        group_nodes = []
        for i in nodes:
            if not self.pdg.find_parent_pdg_node(i):
                continue
            if self.pdg.find_parent_pdg_node(i)['id:ID'] in group_ids:
                group_nodes.append(i)
        return group_nodes

    def output_features_for_group(self, group_ids, output_path):
        print(output_path)
        feature = {}
        current_pdg_nodes = self.get_nodes_in_group(self.pdg.pdg_nodes, group_ids)
        current_call_nodes = self.get_nodes_in_group(self.total_calls, group_ids)
        # print(group_ids)
        # print(self.sensitive_calls)
        current_sensitive_call_nodes = self.get_nodes_in_group(self.sensitive_calls, group_ids)
        # current_pdg_edges = [i for i in self.pdg.pdg_edges if i['start:START_ID'] in group_ids and i['end:END_ID'] in group_ids]
        feature.setdefault('size', len(current_pdg_nodes))
        feature.setdefault('total_call_counts', len(current_call_nodes))
        feature.setdefault('sensitive_call_counts', len(current_sensitive_call_nodes))
        structural_feature = {
            'loop_counts': len(self.get_nodes_in_group(self.loop_nodes, group_ids)), 
            'branch_counts': len(self.get_nodes_in_group(self.branch_nodes, group_ids)), 
            'exception_counts': len(self.get_nodes_in_group(self.exception_nodes, group_ids))
        }
        feature.update(structural_feature)

        for sensitive_call_node in current_sensitive_call_nodes:
            sensitive_node_feature = {}
            sensitive_node_feature.setdefault('string_arg', self.get_string_arg(sensitive_call_node))
            current_structural_feature = self.get_sensitive_structural_features(sensitive_call_node)
            sensitive_node_feature.setdefault('structural_feature', current_structural_feature)
            dataflow_nodes = self.get_nodes_in_group(self.get_dataflow_nodes(sensitive_call_node), group_ids)
            sensitive_node_feature.setdefault('dataflow_nodes', [i['real_name'] for i in dataflow_nodes])
            feature.setdefault(sensitive_call_node['real_name'], sensitive_node_feature)
        vec = self.embedding_feature(feature)
        try:
            vec += list(self.graph_embedding(group_ids))
        except RuntimeError:
            return
        with open(output_path, 'w') as f:
            print(self.pdg.file_name, vec, file=f)

    def output_features(self, output_path):
        feature = {}
        # feature.setdefault('size', self.pdg.get_size())
        feature.setdefault('size', len(self.pdg.pdg_nodes))
        feature.setdefault('total_call_counts', self.get_total_call_counts())
        feature.setdefault('sensitive_call_counts', self.get_sensitive_call_counts())
        feature.update(self.get_global_structural_features())
        for sensitive_call_node in self.sensitive_calls:
            # print(sensitive_call_node)
            sensitive_node_feature = {}
            sensitive_node_feature.setdefault('string_arg', self.get_string_arg(sensitive_call_node))
            current_structural_feature = self.get_sensitive_structural_features(sensitive_call_node)
            sensitive_node_feature.setdefault('structural_feature', current_structural_feature)
            dataflow_nodes = self.get_dataflow_nodes(sensitive_call_node)
            sensitive_node_feature.setdefault('dataflow_nodes', [i['real_name'] for i in dataflow_nodes])
            feature.setdefault(sensitive_call_node['real_name'], sensitive_node_feature)
        print(output_path)
        # with open(output_path, 'w') as f:
        #     for i, v in feature.items():
        #         print(i, v, file=f)
        vec = self.embedding_feature(feature)
        group_ids = [i['id:ID'] for i in self.pdg.pdg_nodes]
        if len(group_ids): 
            vec += list(self.graph_embedding(group_ids))

        with open(output_path, 'w') as f:
            print(self.pdg.file_name, vec, file=f)

    def embedding_feature(self, feature):
        '''
        [metadata, [string+structural+len]*len]
        6+402+(1+3+5)*5
        '''
        vec = []
        for i, v in feature.items():
            if type(v) == int:
                vec.append(v)

        # if API in the code
        sensitive_APIs = utils.get_sensitive_API()
        sensitive_API_len = len(sensitive_APIs)
        is_in_feature = [0] * sensitive_API_len
        sensitive_map = utils.get_sensitive_map()
        for API in sensitive_APIs:
            if API in feature.keys():
                is_in_feature[sensitive_map[API]] = 1
        vec.extend(is_in_feature)

        # sensitive call site
        type_map = utils.get_sensitive_type_map()
        sensitive_API_groups = [sensitive_APIs[i[0]-1:i[1]] for i in type_map]
        sensitive_API_len = 5
        for API_group in sensitive_API_groups:
            current_vec = [0] * (1+3+sensitive_API_len)
            for i in [API for API in API_group if API in feature.keys()]:
                current_vec = [x+y for x, y in zip(current_vec, self.get_sensitive_feature(feature[i]))]
            vec.extend(current_vec)

        # for API in sensitive_APIs:
        #     if API in feature.keys():
        #         current_vec = self.get_sensitive_feature(feature[API])
        #     else:
        #         current_vec = [0] * (1+3+sensitive_API_len)
        #     vec.extend(current_vec)
        return vec

    def get_sensitive_feature(self, feature):
        vec = []      
        string_feature = [self.get_string_feature(i) for i in feature['string_arg']]
        string_feature.append(0)      
        vec.append(max(string_feature))
        vec.extend(self.get_structural_feature(feature['structural_feature']))
        vec.extend(self.get_dataflow_feature(feature['dataflow_nodes']))
        return vec

    def get_string_feature(self, string):
        flag = 0
        shell_keywords = ['npx', 'npm', 'curl', 'read', 'wget', 'echo', 'while', 'pwd', 'whoami', 'ssh', 'nc', 'sudo', 'ifconfig', 'touch', 'sh', 'nslookup', 'python']
        tokens = string.replace(';', ' ').split(' ')
        for keyword in shell_keywords:
            if keyword in tokens:
                flag = 3
                break
        if flag == 0:
            for token in tokens:
                result = self.is_sensitive_string(token)
                if result:
                    flag = int(result)
                    break
        return flag

    def is_sensitive_string(self, string):
        result = False
        has_domain = bool(validators.domain(string))
        has_url = bool(validators.url(string))
        has_mac_add = bool(validators.mac_address(string))
        has_ip = bool(validators.ipv4(string)) or bool(validators.ipv6(string))
        has_file_path = is_valid_filepath(string, platform='linux') and string.startswith("/")
        result = (result or has_domain or has_url or has_mac_add or has_ip)
        if has_file_path:
            return 2
        return result

    def get_structural_feature(self, structures):
        loop_structures_len = len([i for i in structures if i in ['AST_FOR', 'AST_WHILE', 'AST_FOREACH']])
        branch_structures_len = len([i for i in structures if i in ['AST_IF', 'AST_SWITCH']])
        exception_structures_len = len([i for i in structures if i in ['AST_TRY']])
        return [loop_structures_len, branch_structures_len, exception_structures_len]

    def get_dataflow_feature(self, dataflow_nodes):
        sensitive_map = utils.get_sensitive_map()
        data_flow_features = [0] * 5 # sensitive_type
        for node in dataflow_nodes:
            if node in sensitive_map.keys():
                data_flow_features[utils.get_sensitive_type(sensitive_map[node])] += 1
        return data_flow_features

    def graph_embedding(self, nodes):
        graph = nx.DiGraph()
        graph_edges = []
        for i in self.pdg.pdg_edges:
            if not (i[1][0] in nodes and i[2][0] in nodes):
                continue
            if i[0] == 'FLOWS_TO':
                weight = 0.3
            else: weight = 0.7
            graph_edges.append((i[1][0], i[2][0], weight))
        graph.add_weighted_edges_from(graph_edges)
        node2vec = Node2Vec(graph, dimensions=64, walk_length=30, num_walks=200, quiet=True)
        model = node2vec.fit(window=10, min_count=1, batch_words=4)
        all_vectors = [model.wv[word] for word in model.wv.index_to_key]
        average_vector = np.mean(all_vectors, axis=0)
        return average_vector

def time_wrapper(file_path, output_path):
    # if file_path in coped_snippets:
    #     return None
    try:
        print(file_path, output_path)
        extra_features(file_path, output_path)
    except FunctionTimedOut:
        return None
    # extra_features(file_path, output_path)

@func_set_timeout(120)
def extra_features(file_path, output_path):
    with open('./tmp/pdg/CopedSnippet.txt', 'a') as f:
        print(file_path, file=f)
    try:
        pdg = PDG(file_path)
        if not pdg.pdg_nodes:
            return 
        extractor = FeatureExtractor(pdg)
        extractor.load_calls()
        extractor.output_features(output_path)

        # groups = pdg.create_igraph()
        # counter = 1
        # for group in groups:
        #     extractor.output_features_for_group(group, output_path+f"@@{counter}")
        #     counter += 1
    except AssertionError:
        # logger.info(f"assertionError {file_path.replace('../snippets/malware/', '../test/')}")
        pass

def main(target_path, output_path):
    # target_path = '../snippets/malware'
    # output_path = '../PDGFeature/malware'
    flag = True
    def breakpoint(file_path):
        nonlocal flag
        if file_path == '../snippets/benign/fibers-5.0.3@20.js':
            flag = True
        return flag
    for file_name in tqdm(os.listdir(target_path), desc='processing'):
        input_file_path = os.path.join(target_path, file_name)
        output_file_path = os.path.join(output_path, file_name)
        if breakpoint(input_file_path):
            try:
                time_wrapper(input_file_path, output_file_path)
            except BaseException:
                logger.error(f"error: {input_file_path}")

def main_multi(target_path, output_path):
    global coped_snippets
    with open('./tmp/pdg/CopedSnippet.txt', 'r') as f:
        coped_snippets = f.read().split('\n')
    with concurrent.futures.ProcessPoolExecutor(max_workers=96) as executor:
        for pkg_name in os.listdir(target_path):
            pkg_path = os.path.join(target_path, pkg_name)
            output_file_path = os.path.join(output_path, pkg_name)
            try:
                future = executor.submit(time_wrapper, pkg_path, output_file_path)
                # try:
                #     result = future.result(timeout=120)
                # except concurrent.futures.TimeoutError:
                #     pass
            except KeyboardInterrupt as e:
                sys.exit()
         

def extra_single_file(file_name):
    target_path = os.path.join('../snippets/malware', file_name)
    output_path = os.path.join('../PDGFeature/malware', file_name)
    time_wrapper(target_path, output_path)

def get_embedding_features(target_path, output_path):
    main_multi(target_path, output_path)

if __name__ == "__main__":
    # malware_target_path = '../snippets/malware_candidate'
    malware_target_path = '../snippets/malware_duplicated'
    malware_output_path = '../PDGFeature/malware_without_callers'
    
    benign_target_path = '../snippets/benign'
    # benign_output_path = '../PDGFeature/benign'
    benign_output_path = '../PDGFeature/benign_without_gd'


    new_target_path = '../snippets/new'
    new_output_path = '../PDGFeature/new_without_callers'

    LLM_target_path = '../snippets/LLM'
    LLM_output_path = '../PDGFeature/LLM'

    main_multi(LLM_target_path, LLM_output_path)
    # main(LLM_target_path, LLM_output_path)
    # extra_single_file('ash.js')
    # extra_features('../snippets/DuplicatedMalware/picket-fe-bundler-2.0.18.tgz@0.js', '../PDGFeature/malware/picket-fe-bundler-2.0.18.tgz@0.js')
