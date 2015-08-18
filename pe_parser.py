#!/usr/bin/python
#coding:utf8

from collections import OrderedDict

DOS_HEADER = OrderedDict()
PE_HEADER = OrderedDict()
DATA_DIRECTORY = OrderedDict()
SECTION_TABLE = OrderedDict()
SECTION_TABLE_ITEM = OrderedDict()
IMPORT_TABLE = OrderedDict()
IMPORT_TABLE_ITEM = OrderedDict()

"""
================Dos Header==================
"""
DOS_HEADER['magic'] = {'Offset':0x00, 'Size':2, 'Value':0x00}
DOS_HEADER['e_lfnew'] = {'Offset':0x3C, 'Size':4, 'Value':0x00}

"""
================PE Header==================
"""
PE_HEADER['pe_sig'] = {'Offset':0x00, 'Size':4, 'Value':0x00}
PE_HEADER['NumberOfSections'] = {'Offset':0x02, 'Size':2, 'Value':0x00}
"""
================Data Directory==================
"""
DATA_DIRECTORY['ImportTable'] = {'Offset':0x68, 'Size':8, 'Value':0x00}
"""
================Section Table==================
"""
SECTION_TABLE['Offset'] = 0x18+0xE0
"""
================Import Table==================
"""
IMPORT_TABLE['Offset'] = 0
"""
init
"""
from loader import r_s2i
file_name = "Reverse.exe"
file_name = "KeePass.exe"
fp = open(file_name, 'rb')

"""
extract Dos Header information: magic, e_lfnew
----------------------------------------------------+
offset      size(byte)      field       value       |
0x00        2               magic       0x4d5a      |
0x3c        4               e_lfnew     0xOffset    |
----------------------------------------------------+
"""
fp.seek(DOS_HEADER['magic']['Offset'])
DOS_HEADER['magic']['Value'] = fp.read(DOS_HEADER['magic']['Size'])
fp.seek(DOS_HEADER['e_lfnew']['Offset'])
DOS_HEADER['e_lfnew']['Value'] = r_s2i(fp.read(DOS_HEADER['e_lfnew']['Size']))

"""
extract PE Header information: pe signature, NumberOfSections

----------------------------------------------------------------+ ----------
offset          size(byte)      field               value       | Dos Header
......                                                          |
----------------------------------------------------------------+ ----------
offset          size(byte)      field               value       | PE Header
e_lfnew         4               Signature           0x50450000  |
......                                                          |
0x02(e_lfnew+4) 4               NumberOfSections                |
----------------------------------------------------------------+ ----------
"""
PE_HEADER['pe_sig']['Offset'] += DOS_HEADER['e_lfnew']['Value']
PE_HEADER['NumberOfSections']['Offset'] += DOS_HEADER['e_lfnew']['Value'] + 4
fp.seek(PE_HEADER['pe_sig']['Offset'])
PE_HEADER['pe_sig']['Value'] = fp.read(PE_HEADER['pe_sig']['Size'])
fp.seek(PE_HEADER['NumberOfSections']['Offset'])
PE_HEADER['NumberOfSections']['Value'] = r_s2i(fp.read(PE_HEADER['NumberOfSections']['Size']))
"""
extract Data Directory information: pe signature, NumberOfSections
--------------------------------------------------------------------+ ----------
offset              size(byte)      field               value       | Dos Header
......                                                              |
--------------------------------------------------------------------+ ----------
offset              size(byte)      field               value       | PE Header
......                                                              |
--------------------------------------------------------------------+ ----------
offset              size(byte)      field               value       | Standard Fields
......                                                              |
--------------------------------------------------------------------+ ----------
offset              size(byte)      field               value       | Windows Specific Fields
......                                                              |
--------------------------------------------------------------------+ ----------
offset              size(byte)      field               value       | Data Directory
0x60(e_lfnew+0x18)  8               ExportTable                     |
0x68(e_lfnew+0x18)  8               ImportTable                     |
......                                                              |
--------------------------------------------------------------------+ ----------
"""
DATA_DIRECTORY['ImportTable']['Offset'] += DOS_HEADER['e_lfnew']['Value'] + 0x18
fp.seek(DATA_DIRECTORY['ImportTable']['Offset'])
import_table_rva = r_s2i(fp.read(4))
import_table_size = r_s2i(fp.read(4))
DATA_DIRECTORY['ImportTable']['Value'] = {'RVA':import_table_rva, 'Size':import_table_size}

"""
extract Data Directory information: pe signature, NumberOfSections
------------------------------------------------------------------------+ ----------
offset                  size(byte)      field                   value   | Dos Header
......                                                                  |
------------------------------------------------------------------------+ ----------
offset                  size(byte)      field                   value   | PE Header
......                                                                  |
------------------------------------------------------------------------+ ----------
offset                  size(byte)      field                   value   | Standard Fields
......                                                                  |
------------------------------------------------------------------------+ ----------
offset                  size(byte)      field                   value   | Windows Specific Fields
......                                                                  |
------------------------------------------------------------------------+ ----------
offset                  size(byte)      field                   value   | Data Directory
......                                                                  |
------------------------------------------------------------------------+ ----------
offset                  size(byte)      field                   value   | Section Table
0x00(e_lfnew+0x18+0xE0) 8               Name                            |
0x08(e_lfnew+0x18+0xE0) 4               VirtualSize                     |
0x0C(e_lfnew+0x18+0xE0) 4               VirtualAddress                  |
0x10(e_lfnew+0x18+0xE0) 4               SizeOfRawData                   |
0x14(e_lfnew+0x18+0xE0) 4               PointerToRawData                |
0x18(e_lfnew+0x18+0xE0) 4               PointerToRelocations            |
0x1C(e_lfnew+0x18+0xE0) 4               PointerToLineNumbers            |
0x20(e_lfnew+0x18+0xE0) 2               NumberOfRelocations             |
0x22(e_lfnew+0x18+0xE0) 2               NumberOfLineNumbers             |
0x24(e_lfnew+0x18+0xE0) 4               Characteristics                 |
------------------------------------------------------------------------+ ----------
"""
SECTION_TABLE['Offset'] += DOS_HEADER['e_lfnew']['Value']

section_items = []
for num in xrange(PE_HEADER['NumberOfSections']['Value']):
    SECTION_TABLE_ITEM = OrderedDict()

    SECTION_TABLE_ITEM['Name'] = {'Offset':0x00, 'Size':0x08, 'Value':0x00}
    SECTION_TABLE_ITEM['VirtualSize'] = {'Offset':0x08, 'Size':0x04, 'Value':0x00}
    SECTION_TABLE_ITEM['VirtualAddress'] = {'Offset':0x0C, 'Size':0x04, 'Value':0x00}
    SECTION_TABLE_ITEM['SizeOfRawData'] = {'Offset':0x10, 'Size':0x04, 'Value':0x00}
    SECTION_TABLE_ITEM['PointerToRawData'] = {'Offset':0x14, 'Size':0x04, 'Value':0x00}
    SECTION_TABLE_ITEM['PointerToRelocations'] = {'Offset':0x18, 'Size':0x04, 'Value':0x00}
    SECTION_TABLE_ITEM['PointerToLineNumbers'] = {'Offset':0x1C, 'Size':0x04, 'Value':0x00}
    SECTION_TABLE_ITEM['NumberOfRelocations'] = {'Offset':0x20, 'Size':0x02, 'Value':0x00}
    SECTION_TABLE_ITEM['NumberOfLineNumbers'] = {'Offset':0x22, 'Size':0x02, 'Value':0x00}
    SECTION_TABLE_ITEM['Characteristics'] = {'Offset':0x24, 'Size':0x04, 'Value':0x00}

    SECTION_TABLE_ITEM['Name']['Offset'] += SECTION_TABLE['Offset'] + num*0x28
    SECTION_TABLE_ITEM['VirtualSize']['Offset'] += SECTION_TABLE['Offset'] + num*0x28
    SECTION_TABLE_ITEM['VirtualAddress']['Offset'] += SECTION_TABLE['Offset'] + num*0x28
    SECTION_TABLE_ITEM['SizeOfRawData']['Offset'] += SECTION_TABLE['Offset'] + num*0x28
    SECTION_TABLE_ITEM['PointerToRawData']['Offset'] += SECTION_TABLE['Offset'] + num*0x28
    SECTION_TABLE_ITEM['PointerToRelocations']['Offset'] += SECTION_TABLE['Offset'] + num*0x28
    SECTION_TABLE_ITEM['PointerToLineNumbers']['Offset'] += SECTION_TABLE['Offset'] + num*0x28
    SECTION_TABLE_ITEM['NumberOfRelocations']['Offset'] += SECTION_TABLE['Offset'] + num*0x28
    SECTION_TABLE_ITEM['NumberOfLineNumbers']['Offset'] += SECTION_TABLE['Offset'] + num*0x28
    SECTION_TABLE_ITEM['Characteristics']['Offset'] += SECTION_TABLE['Offset'] + num*0x28

    fp.seek(SECTION_TABLE_ITEM['Name']['Offset'])
    SECTION_TABLE_ITEM['Name']['Value'] = fp.read(SECTION_TABLE_ITEM['Name']['Size'])

    fp.seek(SECTION_TABLE_ITEM['VirtualSize']['Offset'])
    SECTION_TABLE_ITEM['VirtualSize']['Value'] = r_s2i(fp.read(SECTION_TABLE_ITEM['VirtualSize']['Size']))

    fp.seek(SECTION_TABLE_ITEM['VirtualAddress']['Offset'])
    SECTION_TABLE_ITEM['VirtualAddress']['Value'] = r_s2i(fp.read(SECTION_TABLE_ITEM['VirtualAddress']['Size']))

    fp.seek(SECTION_TABLE_ITEM['SizeOfRawData']['Offset'])
    SECTION_TABLE_ITEM['SizeOfRawData']['Value'] = r_s2i(fp.read(SECTION_TABLE_ITEM['SizeOfRawData']['Size']))

    fp.seek(SECTION_TABLE_ITEM['PointerToRawData']['Offset'])
    SECTION_TABLE_ITEM['PointerToRawData']['Value'] = r_s2i(fp.read(SECTION_TABLE_ITEM['PointerToRawData']['Size']))

    fp.seek(SECTION_TABLE_ITEM['PointerToRelocations']['Offset'])
    SECTION_TABLE_ITEM['PointerToRelocations']['Value'] = r_s2i(fp.read(SECTION_TABLE_ITEM['PointerToRelocations']['Size']))

    fp.seek(SECTION_TABLE_ITEM['PointerToLineNumbers']['Offset'])
    SECTION_TABLE_ITEM['PointerToLineNumbers']['Value'] = r_s2i(fp.read(SECTION_TABLE_ITEM['PointerToLineNumbers']['Size']))

    fp.seek(SECTION_TABLE_ITEM['NumberOfRelocations']['Offset'])
    SECTION_TABLE_ITEM['NumberOfRelocations']['Value'] = r_s2i(fp.read(SECTION_TABLE_ITEM['NumberOfRelocations']['Size']))

    fp.seek(SECTION_TABLE_ITEM['NumberOfLineNumbers']['Offset'])
    SECTION_TABLE_ITEM['NumberOfLineNumbers']['Value'] = r_s2i(fp.read(SECTION_TABLE_ITEM['NumberOfLineNumbers']['Size']))

    fp.seek(SECTION_TABLE_ITEM['Characteristics']['Offset'])
    SECTION_TABLE_ITEM['Characteristics']['Value'] = r_s2i(fp.read(SECTION_TABLE_ITEM['Characteristics']['Size']))

    section_items.append(SECTION_TABLE_ITEM)

SECTION_TABLE['ITEMS'] = section_items

def rva2raw(SECTION_TABLE, rva):
    """
    refer to the book: <<the definitive guide to pe>>
    """
    #print 'rva: {0}'.format(hex(rva))
    for i in xrange(len(SECTION_TABLE['ITEMS']) - 1):
        #print '{0} va {1}'.format(i, hex(SECTION_TABLE['ITEMS'][i]['VirtualAddress']['Value']))
        #print '{0} va {1}'.format(i, hex(SECTION_TABLE['ITEMS'][i+1]['VirtualAddress']['Value']))
        if rva >= SECTION_TABLE['ITEMS'][i]['VirtualAddress']['Value'] and rva < SECTION_TABLE['ITEMS'][i+1]['VirtualAddress']['Value']:
            return (rva - SECTION_TABLE['ITEMS'][i]['VirtualAddress']['Value'] + SECTION_TABLE['ITEMS'][i]['PointerToRawData']['Value'])
    return False

def read_string(fp):
    res = []
    while True:
        tmp = fp.read(1)
        if not ord(tmp):
            return "".join(res)
        else:
            res.append(tmp)

"""
import table was stored in .idata section, the typical file layout was as follow

+-----------------------+
|   Directory Table     |
+-----------------------+
|......                 |
+-----------------------+
|Null Directory Entry   |
+-----------------------+

+-----------------------+
|DLL1 ImportLookupTable |
+-----------------------+
|......                 |
+-----------------------+
|Null                   |
+-----------------------+
+-----------------------+
|DLL2 ImportLookupTable |
+-----------------------+
|......                 |
+-----------------------+
|Null                   |
+-----------------------+
+-----------------------+
|DLL3 ImportLookupTable |
+-----------------------+
|......                 |
+-----------------------+
|Null                   |
+-----------------------+
+-----------------------+
|   HintNameTable       |
+-----------------------+
|......                 |
+-----------------------+

------------------------------------------------------------+ ----------
offset      size(byte)      field                   value   | ImportDirectoryTable
------------------------------------------------------------+ ----------
0x00        4               ImportLookupTableRVA            | item1(dll1)
0x04        4               Time/DateStamp                  |
0x08        4               ForwarderChain                  |
0x0C        4               NameRVA                         |
0x10        4               ImportAddressTableRVA           |
------------------------------------------------------------+ ----------
......                                                      | item2(dll2)
------------------------------------------------------------+ ----------
......                                                      | item3(dll3)
------------------------------------------------------------+ ----------
"""
import_table_raw = rva2raw(SECTION_TABLE, DATA_DIRECTORY['ImportTable']['Value']['RVA'])
IMPORT_TABLE['Offset'] = import_table_raw
import_table_items = []
i = 0
while True:
    IMPORT_TABLE_ITEM = OrderedDict()
    IMPORT_TABLE_ITEM['ImportLookupTableRVA']= {'Offset': 0x00, 'Size':4, 'Value':0x00}
    IMPORT_TABLE_ITEM['TimeStamp']= {'Offset': 0x04, 'Size':4, 'Value':0x00}
    IMPORT_TABLE_ITEM['ForwarderChain']= {'Offset': 0x08, 'Size':4, 'Value':0x00}
    IMPORT_TABLE_ITEM['NameRVA']= {'Offset': 0x0C, 'Size':4, 'Value':0x00}
    IMPORT_TABLE_ITEM['ImportAddressTableRVA']= {'Offset': 0x10, 'Size':4, 'Value':0x00}

    IMPORT_TABLE_ITEM['ImportLookupTableRVA']['Offset'] += import_table_raw + i*0x14
    IMPORT_TABLE_ITEM['TimeStamp']['Offset'] += import_table_raw + i*0x14
    IMPORT_TABLE_ITEM['ForwarderChain']['Offset'] += import_table_raw + i*0x14
    IMPORT_TABLE_ITEM['NameRVA']['Offset'] += import_table_raw + i*0x14
    IMPORT_TABLE_ITEM['ImportAddressTableRVA']['Offset'] += import_table_raw + i*0x14

    i += 1

    fp.seek(IMPORT_TABLE_ITEM['ImportLookupTableRVA']['Offset'])
    IMPORT_TABLE_ITEM['ImportLookupTableRVA']['Value'] = r_s2i(fp.read(IMPORT_TABLE_ITEM['ImportLookupTableRVA']['Size']))

    fp.seek(IMPORT_TABLE_ITEM['TimeStamp']['Offset'])
    IMPORT_TABLE_ITEM['TimeStamp']['Value'] = r_s2i(fp.read(IMPORT_TABLE_ITEM['TimeStamp']['Size']))

    fp.seek(IMPORT_TABLE_ITEM['ForwarderChain']['Offset'])
    IMPORT_TABLE_ITEM['ForwarderChain']['Value'] = r_s2i(fp.read(IMPORT_TABLE_ITEM['ForwarderChain']['Size']))

    fp.seek(IMPORT_TABLE_ITEM['NameRVA']['Offset'])
    IMPORT_TABLE_ITEM['NameRVA']['Value'] = r_s2i(fp.read(IMPORT_TABLE_ITEM['NameRVA']['Size']))

    fp.seek(IMPORT_TABLE_ITEM['ImportAddressTableRVA']['Offset'])
    IMPORT_TABLE_ITEM['ImportAddressTableRVA']['Value'] = r_s2i(fp.read(IMPORT_TABLE_ITEM['ImportAddressTableRVA']['Size']))

    continue_flag = False
    for item in IMPORT_TABLE_ITEM:
        if IMPORT_TABLE_ITEM[item]['Value'] != 0:
            continue_flag = True
    if not continue_flag:
        break

    """
    --------------------------------------------------------------------+ ----------
    Bit(s)      size            Bit field           Description         | ImportLookupTableItem
    --------------------------------------------------------------------+ ----------
    31          1               Ordinal/Name Flag   if set,import by    |
                                                    ordinal,Otherwise,  |
                                                    import by name.     |
    15-0        16              OrdinalNumber       Used only if the    |
                                                    Flag is set         |
    30-0        31              Hint/Name Table RVA 31-bit RVA of       |
                                                    hint/name table     |
                                                    entry, used only    |
                                                    if Flag is 0.       |
    --------------------------------------------------------------------+ ----------

    --------------------------------------------------------+ ----------
    offset      size        field   Description             | hint/name table item
    --------------------------------------------------------+ ----------
    0x00        2           Hint                            |
    0x02        variable    Name                            |
    *           0 or 1      Pad     if necessary, to align  |
                                    the next entry on an    |
                                    even boundary           |
    --------------------------------------------------------+ ----------
    """
    import_lookup_table_items = []
    offset = rva2raw(SECTION_TABLE, IMPORT_TABLE_ITEM['ImportLookupTableRVA']['Value'])
    fp.seek(offset)
    while True:
        ilt_offset = fp.tell()
        ilt_size = 4
        tmp = fp.read(ilt_size)
        if r_s2i(tmp) == 0:
            break
        else:
            import_lookup_table_items.append({"Offset":ilt_offset, "Size":ilt_size, "Value":tmp})
    IMPORT_TABLE_ITEM['ImportLookupTable'] = import_lookup_table_items
    import_table_items.append(IMPORT_TABLE_ITEM)

IMPORT_TABLE['ITEMS'] = import_table_items

def import_lookup_table_item_proc(fp, item):
    if r_s2i(item) >= 80000000:
        return {"type":"ordinal", "ordinal": r_s2i(item[:2])}
    else:
        raw_addr = rva2raw(SECTION_TABLE, r_s2i(item))
        fp.seek(raw_addr)
        hint = r_s2i(fp.read(2))
        name = read_string(fp)
        return {"type":"name", "hint":hint, "name":name}



print "===============Dos Header==============="
print "dos sig: {0}".format(DOS_HEADER['magic']['Value'])
print "e_lfnew: {0}".format(hex(DOS_HEADER['e_lfnew']['Value']))

print "===============PE Header================"
print "pe sig: {0}".format(PE_HEADER['pe_sig']['Value'])
print "NumberOfSection: {0}".format(hex(PE_HEADER['NumberOfSections']['Value']))
print "NumberOfSection Offset: {0}".format(hex(PE_HEADER['NumberOfSections']['Offset']))

print "===============Import Table================"
print "Import Table RVA: {0}".format(hex(DATA_DIRECTORY['ImportTable']['Value']['RVA']))
print "Import Table Size: {0}".format(hex(DATA_DIRECTORY['ImportTable']['Value']['Size']))
print "Import Table Offset: {0}".format(hex(DATA_DIRECTORY['ImportTable']['Offset']))

print "===============Section Table================"
j = 0
for Section in SECTION_TABLE['ITEMS']:
    j += 1
    print "===============Section {0}===============".format(j)
    print "Section: {0}".format(Section['Name']['Value'])
    print "VirtualSize: {0}".format(hex(Section['VirtualSize']['Value']))
    print "VirtualAddress: {0}".format(hex(Section['VirtualAddress']['Value']))
    print "SizeOfRawData: {0}".format(hex(Section['SizeOfRawData']['Value']))
    print "PointerToRawData: {0}".format(hex(Section['PointerToRawData']['Value']))

print "===============Import Table================"
print "raw address of import table: {0}".format(hex(import_table_raw))
print "items in import table:       {0}".format(len(import_table_items))

count = 0
for i in IMPORT_TABLE['ITEMS']:
    count += 1
    #print "ImportLookupTable RVA: {0}, RAW: {1}".format(hex(i['ImportLookupTableRVA']['Value']), hex(rva2raw(SECTION_TABLE, i['ImportLookupTableRVA']['Value'])))
    #print "Name RVA: {0}, RAW: {1}".format(hex(i['NameRVA']['Value']), hex(rva2raw(SECTION_TABLE, i['NameRVA']['Value'])))
    #print "ImportAddressTable RVA: {0}, RAW: {1}".format(hex(i['ImportAddressTableRVA']['Value']), hex(rva2raw(SECTION_TABLE, i['ImportAddressTableRVA']['Value'])))
    fp.seek(rva2raw(SECTION_TABLE, i['NameRVA']['Value']))
    print "+--------------- {0} dll----------------------+".format(count)
    print "|    DLL Name: {0}".format(read_string(fp))
    print "+-------------Import lookup table-----------+"
    for import_lookup_item in i['ImportLookupTable']:
        #print "addr: {0}".format(hex(r_s2i(j['Value'])).upper())
        res = import_lookup_table_item_proc(fp, import_lookup_item['Value'])
        if res['type'] == 'name':
            print "import function: {0}".format(res['name'])
        else:
            print "import function ordinal: {0}".format(res['ordinal'])

fp.close()
