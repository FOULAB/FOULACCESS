#!/usr/bin/env python

import os
import sys

import hashlib
import httplib
import base64
import socket

from xml.dom.minidom import *

RAC_CODE = { 'x'          : 'Unknown error',
             '0x0'        : 'Success',
             '0x4'        : 'Number of arguments does not match',
             '0xc'        : 'Syntax error in xml2cli command',
             '0x408'      : 'Session Timeout',
             '0x43'       : 'No such subfunction',
             '0x62'       : 'Command not supported on this platform for this firmware',
             '0xb0002'    : 'Invalid handle',
             '0x140000'   : 'Too many sessions',
             '0x140002'   : 'Logout',
             '0x140004'   : 'Invalid password',
             '0x140005'   : 'Invalid username',
             '0x150008'   : 'Too many requests',
             '0x15000a'   : 'No such event',
             '0x15000c'   : 'No such function',
             '0x15000d'   : 'Unimplemented',
             '0x170003'   : 'Missing content in POST ?',
             '0x170007'   : 'Dont know yet',
             '0x1a0004'   : 'Invalid sensorname',
             '0x10150006' : 'Unknown sensor error',
             '0x10150009' : 'Too many sensors in sensorlist',
             '0x20308'    : 'Console not available',
             '0x30003'    : 'Console not active',
             '0x3000a'    : 'Console is in text mode',
             '0x3000b'    : 'Console is in VGA graphic mode',
             '0x30011'    : [ 'Console is in Linux mode (no ctrl+alt+del)',
                              'Console is in Windows or Netware mode' ],
             '0xe0003'    : 'Unknown serveraction',
             '0xf0001'    : 'Offset exceeds number of entries in eventlog',
             '0xf0003'    : 'Request exceeds number of entries in eventlog',
             '0xf0004'    : 'Invalid number of events requested'
             }


SEVERITY = { 'x'   : 'Unknown severity. ',
             ''	   : '-',
             '0x1' : 'Unknown',
             '0x2' : 'OK',
             '0x3' : 'Information',
             '0x4' : 'Recoverable',
             '0x5' : 'Non-Critical',
             '0x6' : 'Critical',
             '0x7' : 'Non-Recoverable',
             }

BOGUS_IDS_1650 = [ '0x1010018', '0x1020010', '0x1020018',
                   '0x1020062', '0x1030010', '0x1030018',
                   '0x1030062', '0x1040010', '0x1040018',
                   '0x1050018', '0x1060010', '0x1060018',
                   '0x1060062', '0x1070018', '0x1070062',
                   '0x1080010', '0x1080062', '0x1090010',
                   '0x10a0010', '0x10f0062', '0x1100010',
                   '0x1110010', '0x1120010', '0x1120062',
                   '0x1130010', '0x1140010', '0x1150010',
                   '0x13b0010', '0x13c0010', '0x13f0010',
                   '0x14b0010', '0x14d0010', '0x20e0062',
                   '0x2110062', '0x2160061', '0x2160062',
                   '0x2170061', '0x2170062', '0x2180061',
                   '0x2180062', '0x2190061', '0x2190062',
                   '0x21a0061', '0x21a0062', '0x21b0061',
                   '0x21b0062', '0x21e0010', '0x21e0061',
                   '0x21e0062', '0x21f0061', '0x21f0062',
                   '0x2210010', '0x2220010', '0x2230010',
                   '0x2240010', '0x2250010', '0x2260010',
                   '0x2270010', '0x2280010', '0x2290010',
                   '0x22a0010', '0x22b0010', '0x22c0010',
                   '0x22d0010', '0x22e0010', '0x22f0010',
                   '0x2300010', '0x2310010', '0x2320010',
                   '0x2330010', '0x2340010', '0x2350010',
                   '0x2360010', '0x2370010', '0x2380010',
                   '0x2390010', '0x23a0010', '0x23e0010',
                   '0x2410010', '0x2420010', '0x2430010',
                   '0x2440010', '0x2450010', '0x2460010',
                   '0x2470010', '0x2480010', '0x2530010',
                   ]

BOGUS_IDS_2650 = [ '0x1350010', '0x1360010', '0x2160061',
                   '0x2170061', '0x2180061', '0x2190061',
                   '0x21a0061', '0x21b0061', '0x21c0061',
                   '0x21d0061', '0x21e0060', '0x21e0061',
                   '0x21f0060', '0x21f0061', '0x2d00010',
                   ]

BOGUS_IDS_1750 = [ '0x1060062', '0x1070062', '0x1080062',
                   '0x10f0062', '0x1120062', '0x1030062',
                   '0x1020062', '0x20e0062', '0x2110062',
                   '0x2160062', '0x2170062', '0x2180062',
                   '0x2190062', '0x21a0062', '0x21b0062',
                   '0x21f0062', '0x21e0062', '0x2160061',
                   '0x2170061', '0x2180061', '0x2190061',
                   '0x21a0061', '0x21b0061', '0x21f0061',
                   '0x21e0061', '0x1010010', '0x1020010',
                   '0x1030010', '0x1040010', '0x1080010',
                   '0x1090010', '0x10a0010', '0x1100010',
                   '0x1110010', '0x1120010', '0x1130010',
                   '0x1140010', '0x1150010', '0x21e0010',
                   '0x2210010', '0x2220010', '0x2230010',
                   '0x2240010', '0x2250010', '0x2260010',
                   '0x2290010', '0x22a0010', '0x22b0010',
                   '0x22c0010', '0x22d0010', '0x22e0010',
                   '0x22f0010', '0x2300010', '0x2310010',
                   '0x2320010', '0x2330010', '0x2340010',
                   '0x2350010', '0x2360010', '0x2370010',
                   '0x2380010', '0x2390010', '0x23a0010',
                   '0x13b0010', '0x13c0010', '0x13f0010',
                   '0x2440010', '0x2450010', '0x2460010',
                   '0x2470010', '0x2480010', '0x14a0010',
                   '0x14d0010', '0x14e0010', '0x1500010',
                   '0x1510010', '0x2000010', '0x2570010',
                   '0x10f0060', '0x1120060', '0x1020060',
                   '0x1010018', '0x1020018', '0x1030018',
                   '0x1040018', '0x1050018', '0x1060018',
                   '0x1070018',
                   ]

PROPNAMES = [ 'NAME',
              'SEVERITY',
              'LOW_CRITICAL',
              'LOW_NON_CRITICAL',
              'VAL',
              'UNITS',
              'UPPER_NON_CRITICAL',
              'UPPER_CRITICAL',
              'SENSOR_TYPE',
              ]

DRIVE_SLOT_CODES = { '0'   : 'Good',
                     '1'   : 'No Error',
                     '2'   : 'Faulty Drive',
                     '4'   : 'Drive Rebuilding',
                     '8'   : 'Drive In Failed Array',
                     '16'  : 'Drive In Critical Array',
                     '32'  : 'Parity Check Error',
                     '64'  : 'Predicted Error',
                     '128' : 'No Drive',
                     }

POWER_UNIT_CODES = { '0' : 'AC Power Unit',
                     '1' : 'DC Power Unit',
                     }

BUTTON_CODES = { '0' : 'Power Button Disabled',
                 '1' : 'Power Button Enabled'
                 }

FAN_CONTROL_CODES = { '0' : 'Normal Operation',
                      '1' : 'Unknown',
                      }

INTRUSION_CODES = { '0' : 'No Intrusion',
                    '1' : 'Cover Intrusion Detected',
                    '2' : 'Bezel Intrusion Detected',
                    }

POWER_SUPPLY_CODES = { '1'  : 'Good',
                       '2'  : 'Failure Detected',
                       '4'  : 'Failure Predicted',
                       '8'  : 'Power Lost',
                       '16' : 'Not Present',
                       }

PROCESSOR_CODES = { '1'	 : 'Good',
                    '2'	 : 'Failure Detected',
                    '4'	 : 'Failure Predicted',
                    '8'	 : 'Power Lost',
                    '16' : 'Not Present',
                    }

CODES = { 'button'       : BUTTON_CODES,
          'drive slot'   : DRIVE_SLOT_CODES,
          'fan control'  : FAN_CONTROL_CODES,
          'intrusion'	 : INSTRUSION_CODES,
          'power supply' : POWER_SUPPLY_CODES,
          'power unit'	 : POWER_UNIT_CODES,
          'processor'	 : PROCESSOR_CODES,
          }



    

    

    
    
    
    
