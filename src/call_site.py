from typing import List

from func_info import FuncInfo


class CallSite:
    def __init__(self, call_site_str: str) -> None:
        self.call_site: List[int] = list(
            map(lambda x: int(x), call_site_str.split(':')))

    def is_in_func(self, def_site: List[int]) -> bool:
        if def_site[1] == -1:
            return False

        match list(map(lambda i: self.call_site[i] - def_site[i], range(5))):
            case [0, start_row, _, end_row, _] if start_row > 0 and end_row < 0:
                return True
            case [0, start_row, start_col, end_row, end_col] if start_row == 0 and end_row == 0 and start_col >= 0 and end_col <= 0:
                return True
            case [0, start_row, start_col, end_row, _] if start_row == 0 and end_row < 0 and start_col >= 0:
                return True
            case [0, start_row, _, end_row, end_col] if start_row > 0 and end_row == 0 and end_col <= 0:
                return True
            case _:
                return False
