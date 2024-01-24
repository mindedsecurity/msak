#!/usr/bin/env python3

#########################################
# Local Libs
from libs.crc16modbus import calculate_crc
from libs.modbus_connection import ModBusConnection, ModBus_Packet, ModBus_Request_Packet
from libs.modbus_constants import *
from libs import Payload_Generator
#########################################

import serial
import struct
import traceback
import sys
import argparse

# SETUP LOGGING
import logging
logger = logging.getLogger("M-SAK")
logging.basicConfig(  # filename="std.log",
    format='%(message)s',
    # filemode='w'
)
# Let us Create an object
logger = logging.getLogger()
# Now we are going to Set the threshold of logger to DEBUG
logger.setLevel(logging.DEBUG)

#########################################
# DEFAULTS
DEFAULT_FUNCTION_CODE = 1
DEFAULT_SLAVE_ADDRESS = 1
#########################################


#########################################
# Functions


def pretty_print_packet(packet):
    return packet


def pretty_print_scan(scan_response, data_type='function'):
    for type, responses in scan_response.items():
        print(f'{type}\t')
        for function_code in responses:
            # print(data_type,function_code)
            if data_type == 'function':
                print(
                    f'\t{function_code} {FUNCTION_CODES.get(function_code,"CUSTOM")}')
            elif data_type == 'subfunction':
                print(
                    f'\t{function_code} {DIAGNOSTIC_SUB_FUNCTION_CODES.get(function_code,"CUSTOM")}')
            elif data_type == 'packet':
                print(f'\t{function_code} {pretty_print_packet(function_code)}')


def strtohex(str):
    return ("\\x{}".format('\\x'.join(format(c, '02X') for c in str)))


####
# SlaveID = 1 Byte = 0-255 ( 0 Broadcast / 1-247 Unicast / 248-155 Reserved)
# Function ID = 1 Byte = 1-255 / 127-255 for exception response codes)
# SubFunctionID = 1Byte (only for Diagnostics and custom functions)
# DATA = Depends on FunctionID
# >BB
#######


def payload_from_fuzzer(template):
    return Payload_Generator(template, True)
 

###########################

###########################
# Function:
# We don't need function codes since we're going to loop over them.

def discover_services(modbus_client, slave_address, data):
    """ loops over function codes 1-127
    Args:
        modbus_client (_type_): connection client object
        slave_address (_type_): integer slave id
        data (_type_): data to be sent in the PDU
    """
    results = dict()

    for function_code in range(1, 127):
        logger.info(">>>>>>>>>>>>>>>>>> ", function_code)

        pckt = ModBus_Request_Packet(
            raw_packet=data, packet_type=type, slave_id=slave_address, function_code=function_code, use_crc=args.use_crc)

        print(strtohex(pckt.finalize_packet()))
        response_data = modbus_client.send_and_recv(pckt)
                
        logger.info("Response Data:", response_data,
                    response_data.tohex(), response_data.raw)

        response_exception = response_data.get_exception_id()
        if response_exception:
            results.setdefault(EXC_CODES.get(
                response_exception, response_exception), []).append(function_code)
        else:
            raw_pckt = response_data.raw
            if len(raw_pckt) == 0:
                results.setdefault('NO_RESPONSE', []).append(function_code)
            else:
                results.setdefault('ACCEPTED_WITH_RESPONSE',
                                   []).append(function_code)

    pretty_print_scan(results, data_type='function')



def discover_diagnostic(modbus_client, slave_address, function_code=7, data=None):
    """_summary_

    Args:
        modbus_client (_type_): _description_
        slave_address (_type_): _description_
        function_code (int, optional): _description_. Defaults to 7.
        data (_type_, optional): _description_. Defaults to None.
    """
    results = dict()
    if function_code is None:
        function_code = 7

    for subfunction in range(1, 255):
        print(">>>>>>>>>>>>>>>>>> Data: ", data)
        pckt = ModBus_Request_Packet(
            raw_packet=struct.pack('>H', subfunction)+data, packet_type=type, slave_id=slave_address, function_code=function_code, use_crc=args.use_crc)

        print(strtohex(pckt.finalize_packet()))
        response_data = modbus_client.send_and_recv(pckt)
        
        logger.info("Response Data:", response_data,
                    response_data.tohex(), response_data.raw)
        response_exception = response_data.get_exception_id()
        if response_exception:
            results.setdefault(EXC_CODES.get(
                response_exception, response_exception), []).append(subfunction)
        else:
            raw_pckt = response_data.raw
            if len(raw_pckt) == 0:
                results.setdefault('NO_RESPONSE', []).append(subfunction)
            else:
                results.setdefault('ACCEPTED_WITH_RESPONSE',
                                   []).append(subfunction)

    pretty_print_scan(results, data_type="subfunction")


##################################################
# Scan with custom template
# Eg. '01{R[0,1,"B"]}FF{R[1,2,">H"]}0E{[0,4]}DD'
# 01
#################################################
def discover_by_template(modbus_client, slave_address, function_code, template=None):
    """_summary_

    Args:
        modbus_client (_type_): _description_
        slave_address (_type_): _description_
        function_code (_type_): _description_
        template (_type_, optional): _description_. Defaults to None.

    Raises:
        Exception: _description_
    """
    results = dict()

    prefix = b''
    if slave_address != None:
        prefix = struct.pack('B', slave_address)
    # If Slave address is not set, it is not expected to have
    if slave_address != None and function_code != None:
        prefix += struct.pack('B', function_code)
    elif function_code != None:
        raise Exception("Cannot Set Function Code without a Slave Address")

    payload = payload_from_fuzzer(template)

    for data in payload:

        print(">>>>>>>>>>>>>>>>>> ", data)
        if prefix != '':
            data = prefix + data

    ######################################## send_modbus_request ####
        pckt = ModBus_Request_Packet(
            raw_packet=data, packet_type=type, slave_id=slave_address, function_code=function_code, use_crc=args.use_crc, is_raw=True)

        print(strtohex(pckt.finalize_packet()))
        response_data = modbus_client.send_and_recv(pckt)
        

    #################################################################
        # Check Response:
        if response_data:
            print("Response Data:", response_data,
              response_data.tohex(), response_data.raw)

            response_exception = response_data.get_exception_id()
            if response_exception:
                results.setdefault(EXC_CODES.get(
                    response_exception, response_exception), []).append(data)
            else:
                raw_pckt = response_data.raw
                if len(raw_pckt) == 0:
                    results.setdefault('NO_RESPONSE', []).append(data)
                else:
                    results.setdefault('ACCEPTED_WITH_RESPONSE', []).append(data)

    print(results)


############################################################################
# M-SAK MAIN
# Expecting:
# SERIAL Options: --serial [-p /serial/path/to/com] [--speed SPEED] [--parity PARITY] [--bytesize BYTESIZE] [--stopbits STOPBITS] [--no-crc] [--timeout TIMEOUT]
# TCP Options: --tcp --host HOST [--port PORT] [--timeout TIMEOUT]
# GENERIC Options:  [-v VERBOSITY] [--id SLAVE_ADDRESS] [-f FUNCTION_CODE] [-S] [-D] [-C] [-R] -d DATA_PAYLOAD
#


# if --tcp --host is required and --port is set as default
tcpargs = argparse.ArgumentParser(add_help=False)
tcpargs.add_argument('--tcp', action='store_true',
                     dest='is_tcp', help='Connect through TCP/IP')
tcpargs.add_argument('--host', dest='host',
                     help='The hostname of the ModBus Server')
tcpargs.add_argument('--port', dest='port', type=int,
                     default=502, help='The port of the ModBus Server')

# if type serial
serialargs = argparse.ArgumentParser(add_help=False)
serialargs.add_argument('--serial', action='store_true',
                        dest='is_serial', default=True, help='Connect through Serial (RTU)')
serialargs.add_argument('-p', dest='path',   action='store', default='/dev/ttyUSB0',
                        help='Serial device path (defaults /dev/ttyUSB0)')
serialargs.add_argument('--speed', dest='bauds',  action='store', default=19200,
                        help='Serial device speed (defaults 19200)')
serialargs.add_argument('--parity', dest='parity', action='store', default=serial.PARITY_NONE,
                        help='Serial device parity (defaults NONE \x27N\x27)')
serialargs.add_argument('--bytesize', dest='bytesize', type=int, action='store', default=serial.EIGHTBITS,
                        help='Serial device bytesize (defaults 8)')
serialargs.add_argument('--stopbits', dest='stopbits', type=float, action='store', default=1.0,
                        help='Serial device stopbits (defaults 1)')
serialargs.add_argument('--no-crc', dest='use_crc', action='store_false',
                        help='Do not append the CRC')


parser = argparse.ArgumentParser(parents=[tcpargs, serialargs], formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description="ModBus Swiss Army Knife [M-SAK]. Based on Specification: https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf",
                                 epilog="""
Usage Examples: 
#Create ModBusPacket with PDU for slave 1 function code 3 data \x00\x01 (PDU \x03\x00\x01)
msak --tcp --host 127.0.0.1 --port 5020 --id 1 -f 3 -d '0001' # For TCP (will add the header \x00\x01\x00\x00\x06+PDU > \x00\x01\x00\x00\x00\x04\x01\x03\x00\x01 )
msak --serial -p /dev/ttyUSB0 --id 1 -f 3 -d '0001' # For RTU Serial (will add slaveId and CRC > \x01\x03\x00\x01\x30\x18)

#Create Raw Packet 
msak --serial -p /dev/ttyUSB0 -R -d '010300013018' --no-crc # without CRC

#Scan all function codes:
msak --serial -p /dev/ttyUSB0 -S -d '01030' 

=== ModBus Packet Reminder Schema:

Modbus PDU packet:    *PDU* = <FunctionCode(1Byte)><Data(nBytes)>
Modbus Serial Packet: <SlaveId(1Byte)><*PDU*><CRC16(2Bytes)>
Modbus TCP Packet:    <TransId(2Bytes)>0000<LenghtOfPDU(2Bytes)><SlaveId(1Byte)><*PDU*>

                                 """)
parser.add_argument('-v', dest='verbosity', action='store', type=int, default=1,
                    help='Verbosity Level (0-4)')
parser.add_argument('--timeout', dest='timeout',  action='store', type=float, default=0.3,
                    help='Timeout for Serial Responses (defaults 0.3s)')
parser.add_argument('--id', dest='slave_address', action='store',
                    help='Slave Address (defaults 1)')
parser.add_argument('-f', dest='function_code', type=int,
                    help='Function code (int)')
parser.add_argument('-S', dest='serv_scan', action='store_true',
                    help='Services Scan')
parser.add_argument('-D', dest='diag_scan', action='store_true',
                    help='Diagnostic Scan (defaults Function = 7 )')
parser.add_argument('-C', dest='custom_scan', action='store_true',
                    help='Custom Scan')
parser.add_argument('-R', dest='send_raw', action='store_true',
                    help='Raw Packet')
parser.add_argument('-d', dest='data_payload', required=True,
                    help='Data payload (hexdump style) OR see custom payload definition if using custom scan option -C')
# TODO:
# parser.add_argument('--print-functions', dest='print_functions',
#                     help='print all modbus functions')
args = parser.parse_args()

print(args)
if args.verbosity == 4:
    logger.setLevel(logging.DEBUG)
elif args.verbosity == 3:
    logger.setLevel(logging.INFO)
elif args.verbosity == 2:
    logger.setLevel(logging.WARN)
elif args.verbosity == 1:
    logger.setLevel(logging.ERROR)

logger.debug(args)

modbus_args = {}
if args.is_tcp:
    type = 'tcp'
    args.use_crc = False
    modbus_args = {"host": args.host,
                   "port": args.port, "timeout": args.timeout}
elif args.is_serial:
    type = 'serial'
    modbus_args = {"port": args.path, "bauds": args.bauds, "timeout": args.timeout,
                   "bytesize": args.bytesize,
                   "parity": args.parity, "stopbits": args.stopbits}
else:
    type = None

try:

    # Open serial port
    modbus_client = ModBusConnection(type=type, **modbus_args)

    logger.debug(modbus_client)

    # Modbus RTU read holding registers example
    if args.slave_address is not None:
        slave_address = int(args.slave_address)
    else:
        slave_address = None

    if args.function_code is not None:
        function_code = int(args.function_code)
    else:
        function_code = None

    if args.custom_scan is False:
        try:
            data = bytes.fromhex(args.data_payload.replace(r'\x',''))
        except:
            logger.error(
                "Got error in parsing the data payload. Please ensure using only hexadecimal text")
            sys.exit()
    else:  # CUSTOM DATA PAYLOAD Expects a different type of data payload.
        data = args.data_payload

    if data == b'':
        logger.debug("DATA to NONE")
        data = None

###############################
# Scan Features:

#################################################################
# Scan by Service (FUNCTION_CODE [1-127])
    if args.serv_scan is True:
        if slave_address is None:
            slave_address = 1

        print(modbus_args)
        discover_services(modbus_client, slave_address, data)

#################################################################
# Scan by Diagnostic ( FUNCTION_CODE=7 , SUB_FUNCTION_CODE [1-255])
    elif args.diag_scan is True:
        if slave_address is None:
            slave_address = 1

        discover_diagnostic(modbus_client, slave_address,
                            function_code, data)

#################################################################
# Scan by Template
    elif args.custom_scan is True:
        discover_by_template(
            modbus_client, slave_address, function_code, data)

#################################################################
# Send Raw Packet from -d
    elif args.send_raw is True:
        # Create Raw packet
        pckt = ModBus_Request_Packet(
            raw_packet=data, packet_type=type, function_code=None, use_crc=args.use_crc, is_raw=True)
        print(pckt.finalize_packet())
        response_data = modbus_client.send_and_recv(pckt)
        
        # response_data = modbus_request(
        #     modbus_client, slave_address, function_code, data, check_response=True, is_raw=True)
        print(
            f"==Data Response==\nHas Exception: {response_data.has_exception()}\nHex Content: {response_data.tohex()}")

#################################################################
# Default Packet Send
    else:
        # Expecting Slave Address & Function_code or a full blown data payload
        # Prepare packet using slave id and function conde
        if function_code is None or slave_address is None:
            parser.print_help()
            logger.error(
                "ERROR: Function Code or Slave Address values should be explicitely set when using default packet send.")
            sys.exit()
        # response_data = modbus_request(
        #    modbus_client, slave_address, function_code, data, check_response=True)

        pckt = ModBus_Request_Packet(
            raw_packet=data, packet_type=type, slave_id=slave_address, function_code=function_code, use_crc=args.use_crc)
        print(pckt.finalize_packet())
        response_data = modbus_client.send_and_recv(pckt)

        print(
            f"==Data Response==\nHas Exception: {response_data.has_exception()}\nHex Content: {response_data.tohex()}")

#################################################################

except serial.SerialException:
    logger.error("Error:", args.path, 'Not Found')
except:
    logger.error('ERROR!>>>>>>>>>>>>>>>>>>')
    traceback.print_exc()
finally:
    try:
        modbus_client.close()
    except:
        pass
