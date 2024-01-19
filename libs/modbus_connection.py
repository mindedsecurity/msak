import struct
from libs.crc16modbus import calculate_crc
from pymodbus.client import ModbusSerialClient, ModbusTcpClient, ModbusUdpClient, ModbusTlsClient


# SETUP LOGGING
import logging
logger = logging.getLogger(__file__)
logging.basicConfig(  # filename="std.log",
    format='%(message)s',
    # filemode='w'
)
# Let us Create an object
logger = logging.getLogger()
# Now we are going to Set the threshold of logger to DEBUG
logger.setLevel(logging.DEBUG)


class ModBus_Packet():
    def __init__(self, packet_type, raw_packet):
        self.type = packet_type
        self.raw = raw_packet

    def get_raw_pdu(self):
        if len(self.raw) != 0:
            if self.type == 'tcp':
                return self.raw[7:]
            else:
                return self.raw[1:]

    def get_slave_id(self):
        if len(self.raw) != 0:
            if self.type == 'tcp':
                return self.raw[6]
            else:
                return self.raw[0]

    def get_raw(self):
        return self.raw

    def tohex(self):
        return ("\\x{}".format('\\x'.join(format(c, '02X') for c in self.get_raw())))

    def __str__(self):
        return f"{(self.raw)}"


class ModBus_Request_Packet(ModBus_Packet):
    def __init__(self, raw_packet, packet_type, function_code, slave_id=1, is_raw=False, use_crc=True, trans_id=1):
        self.type = packet_type
        self.function_code = function_code
        self.slave_id = slave_id
        self.raw = raw_packet
        self.trans_id = trans_id
        self.is_raw = is_raw
        if is_raw == False:
            self.pdu = struct.pack(">BB", slave_id, function_code)+self.raw
        else:
            self.pdu = self.raw
        self.is_finalized = False
        if packet_type == 'serial':
            self.use_crc = use_crc
        else:
            self.use_crc = False

    # b'\x00\x01\x00\x00\x00\x06|\x00\x01\x00\x01\x00\x01'
    # b'\x00\x01\x00\x00\x00\x06|\x01\x01\x00\x01\x00\x01'
    # ModBus Tcp is like RTU but with a header (MBAP) and no CRC
    # MBAP Header| PDU
    #       >HHH|BBHH
    # Where Header is
    # 2Bytes TransID|2Bytes ProtoId (0000)|2Bytes Length of the following data
    # Response
    # b'\x00\x01\x00\x00\x00\x04|\x00\x01\x01\x0a'

    def finalize_packet(self):
        if self.is_finalized == True:
            return self.finalized_packet

        self.is_finalized = True
        if self.type == 'tcp':
            self.finalized_packet = struct.pack(
                '>HHH', self.trans_id, 0, len(self.pdu))+self.pdu
        else:
            self.finalized_packet = self.pdu + self.get_crc()
        return self.finalized_packet

    def get_crc(self):
        if self.use_crc:
            return calculate_crc(self.pdu)
        return b''

    def set_use_crc(self, crc):
        self.use_crc = crc

    def get_use_crc(self):
        return self.use_crc


class ModBus_Response_Packet(ModBus_Packet):

    def has_exception(self):
        pdu = self.get_raw_pdu()
        if pdu != None and len(pdu) > 1:
            return (pdu[0] & 0x80) != 0
        else:
            return False

    def get_exception_id(self):
        if self.has_exception():
            return self.get_raw_pdu()[1]
        return None


"""_summary_
ModBusConnection(type, ...)

Raises:
    Exception: _description_
    Exception: _description_
    Exception: _description_
    Exception: _description_

Returns:
    _type_: _description_
"""


class ModBusConnection():
    # types  serial/tcp/udp
    def __init__(self, type='serial', **kwargs):

        if type == None:
            raise Exception("No type specified! It should be serial/tcp/..")
        self.type = type
        self.create_client(**kwargs)
        self.connect()

    def is_tcp(self):
        return self.type == 'tcp'

    def is_serial(self):
        return self.type == 'serial'

    def create_client(self, **kwargs):

        port = kwargs.pop("port", None)
        if port is None:
            raise Exception("Error port must be set")

        if self.type == 'serial':
            bauds = kwargs.get("bauds", None)
            timeout = kwargs.get("timeout", None)
            bytesize = kwargs.get("bytesize", None)
            parity = kwargs.get("parity", None)
            stopbits = kwargs.get("stopbits", None)
            self.client = ModbusSerialClient(port=port, **kwargs)
        elif self.type == 'tcp':
            host = kwargs.pop("host", None)

            self.client = ModbusTcpClient(
                port=5020, host="127.0.0.1", **kwargs)
        elif self.type == 'udp':
            raise Exception("Not Yet Implemented")
            host = kwargs.get("host", None)
            self.client = ModbusUdpClient(port=port, **kwargs)
        elif self.type == 'tls':
            raise Exception("Not Yet Implemented")
            self.client = ModbusTlsClient(port=port, **kwargs)

        return self.client

    def connect(self):
        return self.client.connect()

    def send_raw(self, pckt):
        return self.client.send(pckt)

    def send(self, pckt):
        if self.client.connected == False:
            raise Exception("Not Connected")
        
        if isinstance(pckt, ModBus_Packet):
            prepared_pckt = pckt.finalize_packet()
        else:
            prepared_pckt = pckt
        
        logger.debug(f'Sending: {prepared_pckt}')

        return self.send_raw(prepared_pckt)

### TODO Add managing abrupt disconnections from Server
    def recv_raw(self, size):
        return self.client.recv(size)

    def read_raw(self, size):
        return self.recv(size)

    def recv(self, size=2048):
        return self.read(size)

    def read(self, size=2048):
        pckt = self.recv_raw(size)
        return ModBus_Response_Packet(packet_type=self.type, raw_packet=pckt)

    def close(self):
        return self.client.close()

    def write(self,  pckt, is_raw=False):
        return self.send(pckt, is_raw=is_raw)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: modbus_connection.py type port [host]")
        sys.exit()
    type = sys.argv[1]
    port = sys.argv[2]
    if len(sys.argv) == 4:
        host = sys.argv[3]
    else:
        host = None
    mbdevice = ModBusConnection(
        type=type, port=port, host=host, timeout=0.1)
        #  | tid    | 00    |  len  |cid|fid|Addr   |input #|
    req = b'\x00\x01\x00\x00\x00\x06\x01\x02\x00\x00\x00\x01'
          # \x00\x01\x00\x00\x00\x04\x01\x01\x01\x01'
    #              \x01\x01\x00\x01\x00\x01'
# \x00\x01\x00\x00\x00\x06\x01\x01\x00\x01\x00\x01
    print("Request:", req)
    mbdevice.send(req)

    # print(mbdevice.read_coils(2))
    print("Response", mbdevice.read())
    mbdevice.close()
