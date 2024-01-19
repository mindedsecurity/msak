#########################################
# MODBUS CONSTANTS
FUNCTION_CODES = {
    # TOTAL NUMBER = 1 to 2000 (0x7D0)
    1: '(0x01) Read Coils [FUN_ID|ADDRESS|TOTAL NUMBER| >BHH]',
    # TOTAL NUMBER = 1 to 2000 (0x7D0)
    2: '(0x02) Read Discrete Inputs [FUN_ID|ADDRESS|TOTAL NUMBER| >BHH]',
    # TOTAL NUMBER = 1 to 125 (0x7D)
    3: '(0x03) Read Holding Registers [FUN_ID|ADDRESS|TOTAL NUMBER| >BHH]',
    # TOTAL NUMBER = 0x0001 to 0x007D
    4: '(0x04) Read Input Registers [FUN_ID|ADDRESS|TOTAL NUMBER| >BHH]',
    # Value can be ON=>0xFF00 or OFF=>0x0000
    5: '(0x05) Write Single Coil [FUN_ID|ADDRESS|COIL VALUE| >BHH]',
    # Value = 0x0000 to 0xFFFF
    6: '(0x06) Write Single Register [FUN_ID|ADDRESS|REG VALUE| >BHH]',
    # No data
    7: '(0x07) Read Exception Status (Serial Line only) [FUN_ID >B]',
    # Needs Sub-function codes supported by the serial line devices
    8: '(0x08) Diagnostics (Serial Line only) [|FUN_ID|SUB_FUN|VALUES| >BHN*H]',
    #  9: (0x09) RESERVED
    # 10: (0x0A) RESERVED
    11: '(0x0B) Get Comm Event Counter (Serial Line only) [FUN_ID >B]',
    12: '(0x0C) Get Comm Event Log (Serial Line only)[FUN_ID >B]',
    # 13 : (0x0D) RESERVED
    # 14 : (0x0E) RESERVED
    15: '(0x0F) Write Multiple Coils [FUN_ID|ADDRESS|TOTAL NUM|BYTE COUNT|BYTE VALS >BHHBN*B]',
    16: '(0x10) Write Multiple registers [FUN_ID|ADDRESS|TOTAL NUM|BYTE COUNT|VALS >BHHBN*H]',
    17: '(0x11) Report Server ID (Serial Line only)  [FUN_ID >B]',
    # 18 : (0x12) RESERVED
    # 19 : (0x13) RESERVED
    20: '(0x14) Read File Record',  # TODO Needs specific format
    21: '(0x15) Write File Record',  # TODO Needs specific format
    22: '(0x16) Mask Write Register',  # TODO
    23: '(0x17) Read/Write Multiple registers',  # TODO
    24: '(0x18) Read FIFO Queue',  # TODO
    # 24-42 RESERVED
    # TODO 43/13 43/14 Needs Specific format
    43: '(0x2B) Encapsulated Interface Transport'  # TODO
    # 25-127 RESERVED
    # 128-255 are reserved as RESPONSE Errors (0x80+REQUESTED FUNCTION CODE)
}

DIAGNOSTIC_SUB_FUNCTION_CODES = {
    0: '0x00 Return Query Data',
    1: '0x01 Restart Communications Option',
    2: '0x02 Return Diagnostic Register',
    3: '0x03 Change ASCII Input Delimiter',
    4: '0x04 Force Listen Only Mode',
    # 05.. 09 RESERVED',
    10: '0x0A  Clear Counters and Diagnostic Register',
    11: '0x0B  Return Bus Message Count',
    12: '0x0C  Return Bus Communication Error Count',
    13: '0x0D  Return Bus Exception Error Count',
    14: '0x0E  Return Server Message Count',
    15: '0x0F  Return Server No Response Count',
    16: '0x10  Return Server NAK Count',
    17: '0x11  Return Server Busy Count',
    18: '0x12  Return Bus Character Overrun Count',
    19: '0x13  RESERVED',
    20: '0x14  Clear Overrun Counter and Flag',
    # 21 ... 65535 RESERVED'
}

EXC_CODES = {
    0x1: 'ILLEGAL FUNCTION',
    0x2: 'ILLEGAL DATA ADDRESS',
    0x3: 'ILLEGAL DATA VALUE',
    0x4: 'SERVER DEVICE FAILURE',
    0x5: 'ACKNOWLEDGE',
    0x6: 'SERVER DEVICE BUSY',
    0x7: 'NEGATIVE ACKNOWLEDGE',
    0x8: 'MEMORY PARITY ERROR',
    # Missing 0x09??
    0xA: 'GATEWAY PATH UNAVAILABLE',
    0xB: 'GATEWAY TARGET DEVICE FAILED TO RESPOND'
}
#########################################