class SyxRequest():
    def __init__(self, fuzzer_input_offset, length, payload):
        self.length = length
        self.fuzzer_input_offset = fuzzer_input_offset
        self.payload = payload[:]
        
    def pack(self):
        return {
            "fuzzer_input_offset": self.fuzzer_input_offset,
            "length": self.length,
            "payload": self.payload
        }
        
    def unpack(packed_syx_request):
        return SyxRequest(
            packed_syx_request["fuzzer_input_offset"],
            packed_syx_request["length"],
            packed_syx_request["payload"]
        )
    
    def get_payload(self):
        return self.payload
    
    def print(self):
        print(f"fuzzer_input_offset: {self.fuzzer_input_offset}")
        print(f"length: {self.length}")
        print(f"payload: {self.payload[:20]}")
    
    def __eq__(self, __o) -> bool:
        return self.fuzzer_input_offset == __o.fuzzer_input_offset and self.length == __o.length
