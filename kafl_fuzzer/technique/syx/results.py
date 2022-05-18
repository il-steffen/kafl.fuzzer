import os
import struct
# Result structure:
# - RIP (Quad)
# - input to take the other branch (length depends on symbolic range)
class Results:
    def __init__(self, result_f_path):
        os.mkfifo(result_f_path)
        self.result_fd = os.open(result_f_path, os.O_RDONLY | os.O_SYNC | os.O_NONBLOCK)
        self.results = []
        
    def new_run(self, initial_payload, fuzz_offset, size):
        self.result_fmt = f"<Q{size}s"
        self.size = struct.calcsize(self.result_fmt)
        self.fuzz_input_offset = fuzz_offset
        self.payload = initial_payload[:]
    
    def collect(self):
        size = os.read(self.result_fd, 8)
        size = struct.unpack("<Q", size)[0]
        
        print(f"Flushing {size} results.")

        for _ in range(size):
            res = os.read(self.result_fd, self.size)
            assert(len(res) == self.size)
            result = struct.unpack(self.result_fmt, res)
            # hexdump(result[1])
            # Ignoring RIP for now. Could be useful later on.
            self.results.append(result[1])
        
    def print_results(self):
        print(f"{len(self.results)} new inputs found with SYX.")
        for i, result in enumerate(self.results):
            print(f"\t- Result {i}:")
            print(f"\t\t- RIP: 0x{result[0]:x}")
            print(f"\t\t- Data: {result[1][:20]}")
            print("")
        print("\n")
    
    def get_new_inputs(self):
        if len(self.results) == 0:
            return []
    
        offset = self.fuzz_input_offset
        replace_len = len(self.results[0])

        def mutate_payload(result):
            assert(len(result) == replace_len)
            payload = bytearray(self.payload)
            payload[offset:offset+replace_len] = bytearray(result)
            
            return payload
            
        return list(map(mutate_payload, self.results))
