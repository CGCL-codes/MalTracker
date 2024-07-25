'''
parse an access path of a function to a structured object
'''
import re
from utils import last_line_col
from utils import get_sensitive_API
from utils import get_func_type
from typing import List


class FuncInfo:
    def __init__(self, filepath: str, def_site: str) -> None:
        self.filepath = filepath
        self.def_site = def_site
        self.def_site = self.get_def_site(def_site)
        self.summary = self.get_summary()
        self.sensitive_info = self.get_sensitive_info()

    def get_def_site(self, def_site):
        splited_site = str.split(def_site, ':')
        if '?' in splited_site:
            return [def_site[0], -1, -1, -1, -1]
        else:
            splited_int = list(map(int, splited_site))
            self.def_site = splited_int
            # start of a file
            if splited_int[1] == 1 and splited_int[2] == 1:
                line_count, last_col_count = last_line_col(self.filepath)
                # end of a file
                if splited_int[3] == line_count and splited_int[4] == last_col_count:
                    return [splited_int[0], -1, -1, -1, -1]
            return splited_int

    def get_sensitive_info(self):
        if "mockbuiltin" not in self.filepath:
            return False
        sensitive_APIs = get_sensitive_API()
        for sensitive_API in sensitive_APIs:
            library_id, API_id = sensitive_API.split(".")
            if library_id in self.filepath and API_id in self.summary:
                return 'SINK'
        return False

    def get_summary(self) -> str:
        if self.def_site is None:
            return f'Unknown func in {self.filepath}'

        start_line, start_col, end_line, end_col = self.def_site[1:]

        # if entry function then return
        if self.is_entry_func():
            return f'File entry {self.filepath}'

        with open(self.filepath) as f:
            for i in range(start_line - 1):
                f.readline()

            lines: list(str) = []
            # line 1-indexed, so end_line + 2 to reach the real end line
            for i in range(start_line, end_line + 2):
                line = f.readline()
                if i == start_line:
                    lines.append(line[start_col - 1:])
                elif i == end_line - 1:  # last line
                    lines.append(line[:end_col])
                else:
                    lines.append(line)
        text = ''.join(lines)
        fn_re = r'^((async\s+)?(function\s+\w+\s*\([:\w\s,]*\)|\([:\w\s,]*\)(\s*:.*)\s*=>\s*))'
        matches = re.findall(fn_re, text)
        if len(matches) > 0:
            return matches[0][0]
        else: return text[:30] + '...'

    def is_entry_func(self) -> bool:
        if self.def_site is not None and self.def_site[1] == -1:
            return True
        return False
