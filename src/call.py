from call_site import CallSite

class Call:
    def __init__(self, caller_idx: int, callee_idx: int, call_site: CallSite) -> None:
        self.caller_idx = caller_idx
        self.callee_idx = callee_idx
        self.call_site = call_site
