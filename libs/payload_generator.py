import itertools
import struct
import random
# Template Format:
# Use dynamic data between brackets {}
# - Dynamic payload expects R[min,max,'B|H'] for range interval data
# - Simple array [00,0B,0A] to generate discrete bytes.
# all constants are considered in hexadecimal format (00 - FF)
# Example:
# '{[0,1]}0A{R[0,1,"B"]}FF{R[1,2,">H"]}0E{[0,4]}DD'
# Will generate:
# b'\x00\n\x00\xff\x00\x01\x0e\x00\xdd'
# b'\x00\n\x00\xff\x00\x01\x0e\x04\xdd'
# b'\x00\n\x00\xff\x00\x02\x0e\x00\xdd'
# b'\x00\n\x00\xff\x00\x02\x0e\x04\xdd'
# b'\x00\n\x01\xff\x00\x01\x0e\x00\xdd'
# b'\x00\n\x01\xff\x00\x01\x0e\x04\xdd'
# b'\x00\n\x01\xff\x00\x02\x0e\x00\xdd'
# b'\x00\n\x01\xff\x00\x02\x0e\x04\xdd'
# b'\x06\n\x00\xff\x00\x01\x0e\x00\xdd'
# b'\x06\n\x00\xff\x00\x01\x0e\x04\xdd'
# b'\x06\n\x00\xff\x00\x02\x0e\x00\xdd'
# b'\x06\n\x00\xff\x00\x02\x0e\x04\xdd'
# b'\x06\n\x01\xff\x00\x01\x0e\x00\xdd'
# b'\x06\n\x01\xff\x00\x01\x0e\x04\xdd'
# b'\x06\n\x01\xff\x00\x02\x0e\x00\xdd'
# b'\x06\n\x01\xff\x00\x02\x0e\x04\xdd'
##
# TODO
# - Variable Length @0,5[0,3,'B'] becomes an array sized from 0 to 5 elements.


class Payload_Generator():
    def __init__(self, template, loop_on_first = False) -> None:
        self.template = template
        self.loop_on_first = loop_on_first
        self.generate()

    def parse_data(self, data):
        return eval(data)

    def create_range_pack(self, values):
        return [struct.pack(values[2], num)
                for num in range(values[0], values[1] + 1)]

    def create_bytes_array(self, values):
        return [struct.pack('B', el) for el in values]

    def create_list_from_file(self, file_name):
        #file_name = spec[1:]
        lines = (line for line in open(file_name.strip()))
        line = (bytes(s.rstrip().encode('ascii')) for s in lines)    
        return line
    
    def generate(self):
        parts = self.template.split('{')
        packed_values = []

        for part in parts:
            if '}' in part:
                spec, rest = part.split('}', 1)
                first_char = spec[0]
                # packed byte array format: min, max, format (Eg. 0,4,'>H')
                if first_char == 'R': # Eg. {R[1,4,'B']} generates a sequence 1-4 and encodes it as a single Byte (See struct.pack)
                    values = self.parse_data(spec[1:])
                    # print(values)
                    packed_values.append(self.create_range_pack(values))
                elif first_char == 'r':#random bytes r[length,number of elements] (Eg. {r[2,4]})
                    values = self.parse_data(spec[1:])
                    values = [random.randbytes(values[0]) for i in range(values[1])]
                    packed_values.append(values)
                elif first_char == '[':
                    values = self.parse_data(spec)
                    packed_values.append(self.create_bytes_array(values))
                elif first_char == '@':
                    values = self.create_list_from_file(spec[1:])
                    packed_values.append(values)
                #TODO Password bruteforce style generator (This one is not performant .. USE a more efficent Generator)
                #elif first_char == 'P':
                #     values = (bytes(''.join(i).encode("ascii")) for i in itertools.product("ABCD1234",repeat=8))
                #     packed_values.append(values)
                else:
                    raise Exception(f'Parsing Error on {spec}')
                #  packed_values.append([struct.pack(values[2], num)
                #                       for num in range(values[0], values[1] + 1)])
                packed_values.append([bytes.fromhex(rest)])
            else:
                packed_values.append([bytes.fromhex(part)])
        if self.loop_on_first:
            packed_values.reverse()
        self.generated_payloads = itertools.product(*packed_values)
        return self.generated_payloads

    ########################
    #### Iterator Stuff ####
    def __next__(self):
        return self.get_next()

    def __iter__(self):
        return self

    def get_next(self):
        if self.loop_on_first == True:
            return b''.join(next(self.generated_payloads)[::-1])
        return b''.join(next(self.generated_payloads))


if __name__ == "__main__":
    template = '{[0,6]}0A{R[0,1,"B"]}FF{R[1,2,">H"]}0E{[0,4]}DD'
    import sys 
    template = sys.argv[1]
    payload = Payload_Generator(template,True)
    for i in payload:
        print(i)
