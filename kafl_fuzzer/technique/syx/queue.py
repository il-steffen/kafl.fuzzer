import queue
from typing import List
from kafl_fuzzer.common.logger import logger
from kafl_fuzzer.technique.syx.request import SyxRequest

class SyxQueue:
    def __init__(self):
        self.queue: List[SyxRequest] = []
        self.issued_requests: List[SyxRequest] = []
    
    def is_interesting_request(self, request: SyxRequest) -> bool:
        for x in self.queue:
            if x == request:
                return False
            
        for x in self.issued_requests:
            if x == request:
                return False
        
        return True
    
    def add(self, e: SyxRequest):
        if self.is_interesting_request(e):
            logger.debug("[SyxQueue] Adding new request")
            logger.debug(f"[SyxQueue] Payload: {e.get_payload()[:20]}")
            logger.debug(f"[SyxQueue] Len: {e.length}")
            logger.debug(f"[SyxQueue] Offset: {e.fuzzer_input_offset}")
            self.queue.append(e)
            return True
        return False
    
    def get(self):
        req = self.queue.pop(0)
        self.issued_requests.append(req)
        return req
    
    def is_empty(self):
        return len(self.queue) == 0
        
    def print(self):
        print(f"Queue content ({len(self.queue)} elements):")
        for x in self.queue:
            x.print()
        print("")
