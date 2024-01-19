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

...

# ModBus TODO


# ModBus Slave tests

```python3 msak.py -h
usage: msak.py [-h] [-p PATH] [--speed BAUDS] [--timeout TIMEOUT] [--parity PARITY] [--bytesize BYTESIZE]
                   [--stopbits STOPBITS] [--id SLAVE_ADDRESS] [-f FUNCTION_CODE] [-S] [-D] [-C] [-R] -d DATA_PAYLOAD
                   [--no-crc] [-v VERBOSITY]

ModBus Swiss Army Knife [M-SAK]. Based on Specification: https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf

options:
  -h, --help           show this help message and exit
  -p PATH              Serial device path (defaults /dev/ttyUSB0)
  --speed BAUDS        Serial device speed (defaults 19200)
  --timeout TIMEOUT    Timeout for Serial Responses (defaults 0.3s)
  --parity PARITY      Serial device parity (defaults NONE 'N')
  --bytesize BYTESIZE  Serial device bytesize (defaults 8)
  --stopbits STOPBITS  Serial device stopbits (defaults 1)
  --id SLAVE_ADDRESS   Slave Address (defaults 1)
  -f FUNCTION_CODE     Function code (int)
  -S                   Services Scan
  -D                   Diagnostic Scan (defaults Function = 7 )
  -C                   Custom Scan
  -R                   Raw Packet
  -d DATA_PAYLOAD      Data payload (hexdump style) OR see custom payload definition if using custom scan option -C
  --no-crc             Do not append the CRC
  -v VERBOSITY         Verbosity Level (0-4)  
  ```

E.g.:

### Service Scan:
It will scan all functions [1-127] using the given payload:
```
python3 modbusak.py -S -d '0001'
Requested Data \x01\x01\x00\x01\x91\xD8
..
Requested Data \x01\x02\x00\x01\x91\xD8
..
Requested Data \x01\x03\x00\x01\x91\xD8
...
```

### Diagnostic Scan:
```
$ python3 modbusak.py -D  -d 0001
>>>>>>>>>>>>>>>>>> Data:  b'\x00\x01'
Requested Data \x01\x07\x00\x01\x00\x01\x24\x0A
.. 
>>>>>>>>>>>>>>>>>> Data:  b'\x00\x01'
Requested Data \x01\x07\x00\x02\x00\x01\xD4\x0A
.... 
```

### Custom Scan 

It's possible to create custom multiple payloads using a template. 
In particular it's possible to use the following special sequences:
 * {R[min,max,pack_format]}: Creates a sequence of numbers from min to max and encodes it using the struct.pack format ('B','>H' etc). It will create (max-min) payloads. 
 * {r{bytesequence_length, ar_len}}: Creates an array of 'ar_len' length where each element is a randome sequence of bytes of 'bytesequence_length' length
 * {[n1, n2, n3 ...]}: Adds to the payload  the numbers and will create a set of payload according to the length of the array. 
 * {@/path/to/file}: using @ char the sequence will be taken from a file.
 * 00-FF: will create a single byte. 
```
python3 modbusak.py -C -d '0001{[0,3]}'

will scan the slave using the following 2 payloads:
b'\x00\x01\x00'
b'\x00\x01\x03'

python3 modbusak.py -C -d '0001{R[0,3,">H"]}FF{r[3,2]}00'

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