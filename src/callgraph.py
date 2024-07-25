import json
import os
from typing import List, Set, Dict
from call import Call
from func_info import FuncInfo
from utils import first_index_of
from collections import deque
from call_site import CallSite


'''
read callgraph json and parse it
'''

class Callgraph:
    # filepath is the json file, not the project path
    def __init__(self, project_base_dir, filepath):
        with open(filepath, 'r') as f:
            content = json.load(f)
        self.project_base_dir = project_base_dir
        self.entries = self.resolve_files(content['entries'])
        self.files = self.resolve_files(content['files'])
        self.functions = [
            self.get_func_info(def_site) for _, def_site in content['functions'].items()
        ]
        self.call2fun = content['call2fun']
        # print(self.call2fun, type(self.call2fun))
        # print(self.call2fun[0], type(self.call2fun[0]))
        # [
        #     str(edge[0]) edge[1] for edge in content['call2fun']
        # ]
        self.calls: Dict[str, Call] = self.get_calls(content['calls'])
        self.fun2fun = [
            (edge[0], edge[1]) for edge in content['fun2fun']
        ]
        self.reachable_idxs = self.get_reachable_func_idxs()

    def resolve_files(self, files: List[str]) -> List[str]:
        if self.project_base_dir == '':
            return files
        return [
            os.path.join(self.project_base_dir, file) for file in files
        ]

    def get_func_info(self, def_site: str) -> FuncInfo:
        file_idx = int(str.split(def_site, ':')[0])
        return FuncInfo(self.files[file_idx], def_site)

    def get_reachable_func_idxs(self) -> Set[int]:
        reachable_func_idx_set = set[int]()
        # entry file will be executed
        # reachable tree roots from entry function
        for entry in self.entries:
            file_idx = self.files.index(entry)
            # bfs for each entry
            worklist = deque()

            def cond_entry_func(info: FuncInfo) -> bool:
                return info.def_site == [file_idx, -1, -1, -1, -1]

            entry_func_idx = first_index_of(self.functions, cond_entry_func)
            # assert entry_func_idx is not None
            if entry_func_idx is None:
                return []
            reachable_func_idx_set.add(entry_func_idx)
            
            worklist.append(entry_func_idx)
            while len(worklist) > 0:
                func_idx = worklist.popleft()
                for edge in self.fun2fun:
                    # avoid duplicate
                    if edge[0] == func_idx and edge[1] not in reachable_func_idx_set:
                        reachable_func_idx_set.add(edge[1])
                        worklist.append(edge[1])
        return reachable_func_idx_set

    # kv: <call_site_idx, Call>
    def get_calls(self, calls: Dict[str, str]) -> Dict:
        # res = {}
        res = []
        for call_idx, call_site_str in calls.items():
            call_site = CallSite(call_site_str)
            call_idx = int(call_idx)
            caller_idx = first_index_of(
            self.functions, lambda func: call_site.is_in_func(func.def_site))
            if caller_idx is None:
                caller_idx = first_index_of(self.functions, lambda func: func.def_site[1:] == [
                    -1, -1, -1, -1] and call_site.call_site[0] == func.def_site[0])
            assert (caller_idx is not None)

            try:
                for i in self.call2fun:
                    # print(type(i[0]), type(call_idx))
                    if i[0] == call_idx:
                        # callee_idxs = self.call2fun[call_idx]
                        # res[call_idx] = Call(caller_idx, callee_idx, call_site)
                        res.append(Call(caller_idx, i[1], call_site))
            except KeyError:
                pass
        return res

    def get_calls_by_fun2fun(self, caller_idx: int, callee_idx: int) -> List[Call]:
        res = []
        # for call in self.calls.values():
        for call in self.calls:
            if call.caller_idx == caller_idx and call.callee_idx == callee_idx:
                # print(caller_idx, callee_idx)
                res.append({'call_site': call.call_site.call_site,
                           'callee_idx': call.callee_idx})
        return res
