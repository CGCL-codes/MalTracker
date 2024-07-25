import csv
import os
import utils
from igraph import Graph
import igraph
import networkx as nx
import leidenalg

class PDG:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_name = self.file_path.split('/')[-1]
        self.execute_odgen()
        self.nodes = self.get_nodes()
        self.edges = self.get_edges()
        self.pdg_edges = self.edges
        self.stmt_kinds = self.get_stmt_kinds()
        self.remove_block_stmt()
        self.add_if_dataflow()
        self.load_PDG()
        self.data_flow_graph = self.get_data_flow_graph()
        self.require_map = self.get_require_map()

    def get_size(self):
        with open(self.file_path, "r") as f:
            content = f.read()
        return len(content)

    def execute_odgen(self):
        """execute the tool odgen and specify the output (node file and edge file)"""
        self.node_path = f"./tmp/pdg/fast/{self.file_name}_node.tsv"
        self.edge_path = f"./tmp/pdg/fast/{self.file_name}_rel.tsv"
        # print(self.node_path)
        # print(self.edge_path)
        tool_base_path = '../../tools/fast/'
        self.target_file_path = f"./tmp/pdg/fast/{self.file_name}"
        with open(self.target_file_path, 'w') as f_write:
            with open(self.file_path, 'r') as f_read:
                f_write.write(f_read.read().replace('package', 'package_t'))
        command = f"python {tool_base_path}/generate_graph.py -a -no {self.node_path} -eo {self.edge_path} {self.target_file_path}"
        # python ../../tools/fast/generate_graph.py ../test/pdg.js -ma
        # os.system(command)
        os.popen(f'timeout 180s bash -c "{command}"').read()

    # def read_nodes(self):
    #     with open(self.node_path) as tsv_file:
    #         reader = csv.DictReader(tsv_file, delimiter='\t')
    #         self.nodes = [row for row in reader if row['funcid:int'] in self.target_funcid]

    def get_edges(self):
        node_idxs = [i['id:ID'] for i in self.nodes]
        with open(self.edge_path) as tsv_file:
            reader = csv.DictReader(tsv_file, delimiter='\t')
            # edges = [row for row in reader if row['start:START_ID'] in node_idxs and row['end:END_ID'] in node_idxs and row['type:TYPE'] == 'FLOWS_TO']
            edges = [row for row in reader if row['start:START_ID'] in node_idxs and row['end:END_ID'] in node_idxs]
        return edges

    def remove_block_stmt(self):
        """ find the parent node of the AST_STMT_LIST and convert the child node of stmt to the parent node"""
        self.pdg_edges.pop(0)
        self.pdg_edges.pop(1)
        for stmt_idx in (node['id:ID'] for node in self.nodes if node['type'] == 'AST_STMT_LIST'):
            parent_idx = next((i for i in self.pdg_edges if i['type:TYPE'] == 'FLOWS_TO' and i['end:END_ID'] == stmt_idx), None)
            if parent_idx is None:
                continue
            child_idxs = [i for i in self.pdg_edges if i['type:TYPE'] == 'PARENT_OF' and i['start:START_ID'] == stmt_idx]
            # self.pdg_edges.extend([{'start:START_ID': parent_idx['start:START_ID'], 'end:END_ID': child_idx['end:END_ID'], 'type:TYPE': 'FLOWS_TO'} for child_idx in child_idxs])
            if len(child_idxs):
                self.pdg_edges.append({'start:START_ID': parent_idx['start:START_ID'], 'end:END_ID': child_idxs[0]['end:END_ID'], 'type:TYPE': 'FLOWS_TO'})
            self.pdg_edges = [edge for edge in self.pdg_edges if stmt_idx not in (edge['start:START_ID'], edge['end:END_ID'])]

    def get_nodes(self):
        """cope with the odgen output, only keep the target funcid"""
        with open(self.node_path) as tsv_file:
            reader = csv.DictReader(tsv_file, delimiter='\t')
            all_nodes = [row for row in reader]
        self.all_nodes = all_nodes
        begin_node = next((node for node in all_nodes if self.file_name in node['name'] and node['type'] == 'AST_TOPLEVEL'), None)
        assert begin_node is not None
        end_node = next((node for node in all_nodes if node['type'] in ('AST_TOPLEVEL', 'BASE_SCOPE') and int(node['id:ID']) > int(begin_node['id:ID'])), None)
        assert end_node is not None
        return all_nodes[int(begin_node['id:ID']):int(end_node['id:ID'])]
        
    def get_stmt_kinds(self):
        """ get the stmts PDG will keep compared to AST """
        target_stmts = list(set([self.find_node_by_idx(edge[i])['type'] for edge in self.edges if edge['type:TYPE'] == 'FLOWS_TO' for i in ['start:START_ID', 'end:END_ID']]))
        for stmt in ('AST_STMT_LIST', 'CFG_FUNC_ENTRY', 'CFG_FUNC_EXIT'):
            utils.remove_if_existing(target_stmts, stmt)
        return target_stmts

    def add_if_dataflow(self):
        """change some data flow of odgen"""
        for edge in (edge for edge in self.pdg_edges if edge['type:TYPE'] == 'OBJ_REACHES' and self.find_node_by_idx(edge['end:END_ID'])['type'] == 'AST_BINARY_OP'):
            nearest_stmt = self.find_nearest_stmt(edge['end:END_ID'])
            self.pdg_edges.append({'start:START_ID': edge['start:START_ID'], 'end:END_ID': nearest_stmt['id:ID'], 'type:TYPE': 'OBJ_REACHES'})

    def find_node_by_idx(self, idx):
        return next((node for node in self.nodes if node['id:ID'] == idx), None)

    def find_nearest_stmt(self, idx):
        current_node = self.find_node_by_idx(idx)
        while current_node['type'] not in self.stmt_kinds:
            # print(current_node['id:ID'])
            current_node = self.find_begin_by_end(current_node['id:ID'])
        return current_node

    def find_begin_by_end(self, end_idx):
        return self.find_node_by_idx(next((i['start:START_ID'] for i in self.edges if i['end:END_ID'] == end_idx and i['type:TYPE'] == 'PARENT_OF'), None))

    def find_ends_by_begin(self, begin_idx):
        return [self.find_node_by_idx(i['end:END_ID']) for i in self.edges if i['start:START_ID'] == begin_idx and i['type:TYPE'] == 'PARENT_OF']

    def load_PDG(self):
        showed_attrs = ['id:ID', 'code', 'type']
        pdg_edge_types = ['FLOWS_TO', 'OBJ_REACHES']
        pdg_edges = []
        self.pdg_nodes = []
        for edge in (edge for edge in self.pdg_edges if edge['type:TYPE'] in pdg_edge_types):
            start_node = self.find_node_by_idx(edge['start:START_ID'])
            end_node = self.find_node_by_idx(edge['end:END_ID'])

            if start_node['type'] not in self.stmt_kinds or end_node['type'] not in self.stmt_kinds:
                continue
            # print((edge['type:TYPE'], [start_node[i] for i in showed_attrs], [end_node[i] for i in showed_attrs]))
                
            pdg_edge = (edge['type:TYPE'], [start_node[i] for i in showed_attrs], [end_node[i] for i in showed_attrs])
            utils.add_if_not_existing(pdg_edges, pdg_edge)
            utils.add_if_not_existing(self.pdg_nodes, start_node)
            utils.add_if_not_existing(self.pdg_nodes, end_node)
        self.pdg_edges = pdg_edges

    def output_PDG(self):
        for pdg_edge in self.pdg_edges:
            print(pdg_edge)

    def find_parent_pdg_node(self, node):
        """ find the pdg node for method call nodes """
        while True:
            # assert node is not None
            if node is None:
                return None
            if node in self.pdg_nodes:
                break
            node = self.find_begin_by_end(node['id:ID'])
        return node

    def find_edges_by_nodes(self, begin_node, end_node):
        return [edge for edge in self.edges if edge['start:START_ID'] == begin_node['id:ID'] and edge['end:END_ID'] == end_node['id:ID']]

    def get_nodes_by_type(self, node_type):
        if type(node_type) == str:
            node_type = [node_type]
        return [node for node in self.nodes if node['type'] in node_type]
    
    def get_data_flow_graph(self):
        edges = []
        for edge in self.edges:
            # if (edge['start:START_ID'] == begin_node['id:ID'] and edge['type:TYPE'] == 'OBJ_REACHES') or \
            # (edge['end:END_ID'] == end_node['id:ID'] and edge['type:TYPE'] == 'OBJ_REACHES'):
            if edge['type:TYPE'] == 'OBJ_REACHES' and (edge['start:START_ID'], edge['end:END_ID']) not in edges:
                edges.append((edge['start:START_ID'], edge['end:END_ID']))
        edges = list(set(edges))
        if not edges:
            return None
        g = Graph.TupleList(edges, directed=True)
        return g
    
    def get_require_map(self):
        require_map = {}
        for node in self.nodes:
            if node['flags:string[]'] in ('JS_REQUIRE_BUILTIN', 'JS_REQUIRE_EXTERNAL'):
                require_node = self.find_begin_by_end(node['id:ID'])
                if require_node['type'] != 'AST_ASSIGN':
                    continue
                # print(require_node)
                var_name = self.find_ends_by_begin(self.find_ends_by_begin(require_node['id:ID'])[0]['id:ID'])[0]['code']
                required_lib_name = self.find_ends_by_begin(self.find_ends_by_begin(node['id:ID'])[-1]['id:ID'])[0]['code']
                require_map.setdefault(var_name, required_lib_name)
        try:
            require_map.pop('')
        except KeyError:
            pass
        return require_map

    def create_igraph(self):
        g = Graph(directed=True)
        nodes_idx = [i.get('id:ID') for i in self.pdg_nodes]
        g.add_vertices(len(nodes_idx))
        g.vs['id'] = nodes_idx
        edges_idx = [(i[1][0], i[2][0]) for i in self.pdg_edges]
        edges_type = []
        for i in self.pdg_edges:
            if i[0] == 'FLOWS_TO':
                edges_type.append(1)
            elif i[0] == 'OBJ_REACHES':
                edges_type.append(100)

        edges_by_index = [(g.vs.find(id=id1).index, g.vs.find(id=id2).index) for id1, id2 in edges_idx]
        g.add_edges(edges_by_index)
        g.es['weight'] = edges_type
                
        # partition = leidenalg.ModularityVertexPartition(g, resolution_parameter=0.01)
        # groups = leidenalg.find_partition(g, partition_type=partition)
        groups = leidenalg.find_partition(g, leidenalg.RBERVertexPartition, weights=g.es["weight"], resolution_parameter=0.01)
        groups_id = [[self.find_node_by_idx(g.vs[i]['id'])['id:ID'] for i in group] for group in groups]
        # for group in groups_id:
        #     print('------------------\n')
        #     for node in group:
        #         print(node)
        # print(groups_id)
        return groups_id

        
        # for i in self.pdg_nodes:
        #     print(i)
        # for i in range(len(edges_idx)):
        #     print(edges_type[i], edges_idx[i])
        # igraph.plot(groups, mark_groups=True)
        # community = g.community_infomap()
        # print(community)

if __name__ == "__main__":    
    pdg = PDG('../tmp/pdg.js')
    pdg.create_igraph()
    pdg.graph_embedding()
    # pdg.output_PDG()
