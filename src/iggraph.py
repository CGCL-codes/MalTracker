from callgraph import Callgraph
import igraph as ig
import leidenalg
from func_info import FuncInfo
from typing import List, Dict


class IGGraph:
    def __init__(self, callgraph: Callgraph) -> None:
        self.callgraph = callgraph
        self.ig_graph = ig.Graph(directed=True)
        self.reachable_idxs = callgraph.get_reachable_func_idxs()
        self.ig_graph.add_vertices(len(self.reachable_idxs))
        self.ig_graph.vs['idx'] = list(self.reachable_idxs)
        for edge in callgraph.fun2fun:
            if edge[0] in self.reachable_idxs and edge[1] in self.reachable_idxs:
                src = self.ig_graph.vs.find(idx=edge[0]).index
                dst = self.ig_graph.vs.find(idx=edge[1]).index
                self.ig_graph.add_edge(src, dst)
        self.sensitive_chains = self.get_sensitive_chain()
        self.sort_sensitive_chain()
        self.get_node_info()
        # self.partition = self.get_partition()
        self.get_sensitive_call_relationship()
    
    def get_node_info(self):
        for vertex_idx in range(len(self.reachable_idxs)):
            # vertex_idx: idx of igraph
            # func_idx/idx: idx of callgraph storing information of func
            func_idx = self.ig_graph.vs[vertex_idx]['idx']
            vertex_info = {}
            callee_func_idxs = [self.ig_graph.vs[i.target]['idx']
                                for i in self.ig_graph.vs[vertex_idx].out_edges()]
            # if func_idx == 296:
            #     print(callee_func_idxs)
            #     print(len(callee_func_idxs))
            func_info: FuncInfo = self.callgraph.functions[func_idx]

            func_info.sensitive_info = self.get_sensitive_attr(func_idx)
            vertex_info['idx'] = func_idx
            vertex_info['def_site'] = func_info.def_site
            vertex_info['summary'] = func_info.summary
            vertex_info['filepath'] = func_info.filepath
            vertex_info['is_sensitive'] = func_info.sensitive_info
            func_info.calls = [
                call for callee_func_idx in callee_func_idxs for call in self.callgraph.get_calls_by_fun2fun(
                    func_idx, callee_func_idx)
            ]
            vertex_info['calls'] = func_info.calls

    def get_partition(self) -> List[List]:
        parts = leidenalg.find_partition(
            self.ig_graph, leidenalg.ModularityVertexPartition)
        res = []
        for cluster in parts:
            func_cluster = []
            for vertex_idx in cluster:
                # vertex_idx: idx of igraph
                # func_idx/idx: idx of callgraph storing information of func
                func_idx = self.ig_graph.vs[vertex_idx]['idx']
                vertex_info = {}
                callee_func_idxs = [self.ig_graph.vs[i.target]['idx']
                                    for i in self.ig_graph.vs[vertex_idx].out_edges()]
                # if func_idx == 296:
                #     print(callee_func_idxs)
                #     print(len(callee_func_idxs))
                func_info: FuncInfo = self.callgraph.functions[func_idx]

                func_info.sensitive_info = self.get_sensitive_attr(func_idx)
                vertex_info['idx'] = func_idx
                vertex_info['def_site'] = func_info.def_site
                vertex_info['summary'] = func_info.summary
                vertex_info['filepath'] = func_info.filepath
                vertex_info['is_sensitive'] = func_info.sensitive_info
                func_info.calls = [
                    call for callee_func_idx in callee_func_idxs for call in self.callgraph.get_calls_by_fun2fun(
                        func_idx, callee_func_idx)
                ]
                vertex_info['calls'] = func_info.calls
                func_cluster.append(vertex_info)
            res.append(func_cluster)
        return res

    def plot(self, target: str):
        ig.plot(self.ig_graph,
                vertex_label=self.ig_graph.vs['idx'], target=target)

    def get_sensitive_chain(self):
        """ get subgraph of the given sensitive node"""
        self.sensitive_functions = []
        sensitive_chains = {"SOURCE":[], "SINK":[]}
        for i in self.callgraph.functions:
            idx = self.callgraph.functions.index(i)
            # get built-in sensitive function
            if i.sensitive_info and idx in self.reachable_idxs:
                sensitive_chains[i.sensitive_info].append([idx])
        # v [[], [], []]
        for k, v in sensitive_chains.items():
            for i in range(len(v)):
                # get node object
                start_node = self.ig_graph.vs.select(idx=v[i][0])[0]
                callers = self.ig_graph.subcomponent(start_node, mode="in")
                v[i] = [self.ig_graph.vs[j]['idx'] for j in callers]
                for j in callers:
                    idx = self.ig_graph.vs[j]['idx']
                    self.callgraph.functions[idx].sensitive_info = 'SINK'
                    self.sensitive_functions.append(j)
        self.sensitive_functions = list(set(self.sensitive_functions))
        return sensitive_chains
    
    def sort_sensitive_chain(self):      
        for _, v in self.sensitive_chains.items():
            v.sort(key=lambda x: len(x))
            for i in v[:]:
                for j in v[:]:
                    if set(i) < set(j) and i in v:
                        v.remove(i)
    
    def get_sensitive_attr(self, idx):
        for i, v in self.sensitive_chains.items():
            for j in v:
                if idx in j:
                    return i
        return False
    
    def get_sensitive_call_relationship(self):
        self.sensitive_relationship = {}
        for i in self.sensitive_functions:
            idx = self.ig_graph.vs[i]['idx']
            callees = [self.ig_graph.vs[self.ig_graph.es[edge_i].target]['idx'] for edge_i in self.ig_graph.incident(i, mode='out') if self.ig_graph.es[edge_i].target in self.sensitive_functions]
            # for edge_i in edge_is:
            #     edge = self.ig_graph.es[edge_i]
            #     print(self.ig_graph.vs[edge.source]['idx'], self.ig_graph.vs[edge.target]['idx'])
            self.sensitive_relationship[idx] = callees

