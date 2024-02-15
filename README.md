![](https://visitor-badge.laobi.icu/badge?page_id=wisec.msak)
# ModBus Swiss Army Knife

The MSAK is a tool written in Python to help discovering and testing exposed standard and custom services of ModBus Servers/Slaves over Serial or TCP/IP connections.
It also offers a highly customizable payload generator that will help the tester to perform complex scans using a simple but powerful templating format.

# Cloning

Use --recurse-submodules

```git clone --recurse-submodules https://github.com/mindedsecurity/msak```

# MSAK Tool

```python3 msak.py -h
usage: msak.py [-h] [--tcp] [--host HOST] [--port PORT] [--serial] [-p PATH] [--speed BAUDS] [--parity PARITY] [--bytesize BYTESIZE] [--stopbits STOPBITS] [--no-crc] [-v VERBOSITY]
               [--timeout TIMEOUT] [--id SLAVE_ADDRESS] [-f FUNCTION_CODE] [-S] [-D] [-C] [-R] -d DATA_PAYLOAD

ModBus Swiss Army Knife [M-SAK]. Based on Specification: https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf

options:
  -h, --help           Show this help message and exit
  --tcp                Connect through TCP
  --host HOST          The hostname of the ModBus Server
  --port PORT          The port of the ModBus Server
  --serial             Connect through Serial (RTU)
  -p PATH              Serial device path (defaults /dev/ttyUSB0)
  --speed BAUDS        Serial device speed (defaults 19200)
  --parity PARITY      Serial device parity (defaults NONE 'N')
  --bytesize BYTESIZE  Serial device bytesize (defaults 8)
  --stopbits STOPBITS  Serial device stopbits (defaults 1)
  --no-crc             Do not append the CRC
  -v VERBOSITY         Verbosity Level (0-4)
  --timeout TIMEOUT    Timeout for Serial Responses (defaults 0.3s)
  --id SLAVE_ADDRESS   Slave Address (defaults 1)
  -f FUNCTION_CODE     Function code (int)
  -S                   Services Scan
  -D                   Diagnostic Scan (defaults Function = 7 )
  -C                   Custom Scan
  -R                   Raw Packet
  -d DATA_PAYLOAD      Data payload (hexdump style) OR see custom payload definition if using custom scan option -C

Usage Examples: 
#Create ModBusPacket with PDU for slave 1 function code 3 data  (PDU )
msak --tcp --host 127.0.0.1 --port 5020 --id 1 -f 3 -d '0001' # For TCP (will add the header +PDU >  )
msak --serial -p /dev/ttyUSB0 --id 1 -f 3 -d '0001' # For RTU Serial (will add slaveId and CRC > 0)

#Create Raw Packet 
msak --serial -p /dev/ttyUSB0 -R -d '010300013018' --no-crc # without CRC

#Scan all function codes:
msak --serial -p /dev/ttyUSB0 -S -d '01030' 

  ```

E.g.:

### Service Scan:
Scan all functions codes [1-127] using the given payload and then will print a summary grouped according to the responses:

```
python3 msak.py -S -d '0001'
Requested Data \x01\x01\x00\x01\x91\xD8
..
Requested Data \x01\x02\x00\x01\x91\xD8
..
Requested Data \x01\x03\x00\x01\x91\xD8
...
```

### Diagnostic Scan:
Scan all diagnostic codes [1-255] using the given payload and then will print a summary grouped according to the responses:
```
$ python3 msak.py -D -d '0001'
>>>>>>>>>>>>>>>>>> Data:  b'\x00\x01'
Requested Data \x01\x07\x00\x01\x00\x01\x24\x0A
.. 
>>>>>>>>>>>>>>>>>> Data:  b'\x00\x01'
Requested Data \x01\x07\x00\x02\x00\x01\xD4\x0A
.... 
```

### Custom Scan 

It's possible to create custom multiple payloads using a templating format. 

In particular it's possible to use the following special sequences:
 * RANGE:  {R[min,max,pack_format]}: Creates a sequence of numbers from min to max and encodes it using the struct.pack format ('B','>H' etc). It will create (max-min) payloads. 
 * RANDOM:  {r{bytesequence_length, ar_len}}: Creates an array of 'ar_len' length where each element is a randome sequence of bytes of 'bytesequence_length' length
 * ARRAY:   {[n1, n2, n3 ...]}: Adds to the payload  the numbers and will create a set of payload according to the length of the array. 
 * FROM FILE: {@/path/to/file}: using @ char the sequence will be taken from a file.
 * CONSTANT:  00-FF: will create a single byte. 

When completed it will print a summary grouped according to the responses.
```
python3 msak.py -C -d '0001{[0,3]}'

will scan the slave using the following 2 payloads:
b'\x00\x01\x00'
b'\x00\x01\x03'

python3 msak.py -C -d '0001{R[0,3,">H"]}FF{r[3,2]}00'

will scann the slave using the following set of generated payloads:
b'\x00\x01\x00\x00\xff\xa3\x91\xa7\x00'
b'\x00\x01\x00\x00\xff6\x9fr\x00'
b'\x00\x01\x00\x01\xff\xa3\x91\xa7\x00'
b'\x00\x01\x00\x01\xff6\x9fr\x00'
b'\x00\x01\x00\x02\xff\xa3\x91\xa7\x00'
b'\x00\x01\x00\x02\xff6\x9fr\x00'
b'\x00\x01\x00\x03\xff\xa3\x91\xa7\x00'
b'\x00\x01\x00\x03\xff6\x9fr\x00'
```

# ModBus Specification

## Over Serial RTU 

Based on https://www.modbus.org/docs/PI_MBUS_300.pdf

Big Endian (most significant byte first)

ADU = | MasterID | PDU | CRC | = |1 Byte MasterID| PDU | 2 Bytes CRCH+CRCL |
 
PDU = | Function ID  | DATA |

MasterID = 1 Byte = 0-255 ( 0 Broadcast / 1-247 Unicast / 248-155 Reserved)

Function ID = 1 Byte = 1-255 / 127-255 for exception response codes)

SubFunctionID = 1Byte (only for Diagnostics and custom functions)

DATA = Depends on FunctionID

## Over TCP/IP

```
Modbus PDU packet:    _PDU_ = <FunctionCode(1Byte)><Data(nBytes)>
Modbus TCP Packet:    <TransId(2Bytes)>0000<LenghtOfPDU(2Bytes)><SlaveId(1Byte)><_PDU_>
```
