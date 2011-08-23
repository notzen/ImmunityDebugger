#!/usr/bin/env python

#-------------------------------------------------------------------------------
# Process Dump Utility for Immunity Debugger 1.83
# Copyright (C) 2011 Kiran Bandla <kbandla@in2void.com>
#-------------------------------------------------------------------------------

__VERSION__  = '0.03'
NAME        = 'Dump'
DESC        = 'Dumps process to disk, fixes IAT'
COPYRIGHT   = '(C) 2011 Kiran Bandla, <kbandla@in2void.com>'
LICENSE     = 'WTFPL'

import immlib
import pefile
import getopt
import struct
from ctypes import *
from pelib import *

DEBUG = True
TAB = 4

def usage(imm):
    imm.log(" ")
    imm.log("PE Dumper [%s] by kbandla" % (NAME), focus=1, highlight=1)
    imm.log("This script will dump a module to disk.")
    imm.log("Options:")
    imm.log("      -m : module name to dump. Default is the loaded module")
    imm.log("      -p : path of dump file. Default is c:\\")
    imm.log("      -h : help")
    imm.log(" ")
    return "See log window (Alt-L) for usage .. "

def dump(name, path):
    """
    Dump a process to disk, and fix some section parameters
    """
    imm = immlib.Debugger()
    path = path+name
    imm.log('[%s] Dumping %s to %s'%(NAME, name, path))
    try:
        module  = imm.getModule(name)
        if not module:
            raise Exception, "Couldn't find %s .." % name
    except Exception,e:
        return 'Error : %s'%e
    start = module.getBaseAddress()
    size = module.getSize()
    imm.log('[%s] Reading 0x%x bytes from 0x%08x'%(NAME, size, start))
    data = imm.readMemory(start, size)

    pe = pefile.PE(data=data)
    imm.log('[%s] Fixing section information..'%NAME)
    for i, section in enumerate(pe.sections):
        if DEBUG:
            imm.log(' '*TAB+'[Section #%s]'%(i))
            imm.log(' '*2*TAB+'PointerToRawData = %s'%(section.PointerToRawData))
            imm.log(' '*2*TAB+'VirtualAddress = %s'%(section.VirtualAddress))
            imm.log(' '*2*TAB+'SizeOfRawData = %s'%(section.SizeOfRawData))
            imm.log(' '*2*TAB+'VirtualSize = %s'%(section.Misc_VirtualSize))
        pe.sections[i].PointerToRawData = section.VirtualAddress
        pe.sections[i].SizeOfRawData = section.Misc_VirtualSize
    try:
        pe.write(filename=path)
    except Exception,e:
        imm.log('[%s] Error : %s'%(NAME,e), focus=1, highlight=1 )
        return 'Error'
    imm.log('[%s] Wrote %s bytes to %s'%(NAME,size, path))
    pe.close()
    return True

def rebuild(filepath, target="c:\sample_fixed.exe"):
    """
    ReBuild IAT
    Fix the IAT for filepath, and write to target
    """
    imm = immlib.Debugger()
    pe = pefile.PE(filepath)
    iat = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
    if not iat:
        imm.log('[%s] Error : No IAT found!', highlight=1)
        return 'Error: No IAT Found!'

    # Read the IAT info from the dumped file on disk
    iat_data = pe.get_data(iat.VirtualAddress, iat.Size)
    imm.log('[%s] Potential IAT found at %08X. Size: %08X'%(NAME, iat.VirtualAddress, iat.Size))

    offset = 0
    function_strings = 0
    addresses = {}  #dict of addresses:
    while True:
        im = ImportDescriptor()
        # Read 20 bytes each time
        descriptor_data = iat_data[offset:offset+im.getSize()]
        if descriptor_data == '\x00'*20:
            # is it the end of the IAT?
            break
        try:
            # See if we can decode the data properly. If not, something is wrong.
            im.get(descriptor_data)
        except Exception,e:
            imm.log('No IAT Found at the location. Quitting.')
            return 'Error. See Log'

        # increment to the next Import Descriptor
        offset+=im.getSize()
        dll_name = str()
        counter = 0
        while True:
            char_ = pe.get_data(im.Name+counter,1)
            if  char_ != '\x00':
                dll_name += char_
                counter += 1
            else:
                break
        if DEBUG:
            imm.log('    Found %s at %08X'%(dll_name, im.Name))

        firstThunk = int(im.FirstThunk)
        thunk_offset = 0
        
        while True:
            address = struct.unpack('<L', pe.get_data(firstThunk+thunk_offset, struct.calcsize('<L')) )
            # k,v : offset:address
            addresses[thunk_offset+firstThunk] = address[0]
            if address[0] == 0x00000000:
                # end of descriptor
                break
            else:
                if DEBUG:
                    func = imm.getFunction(address[0])
                    imm.log('        * %08X [was %s]'%(address[0],func.getName()),address=thunk_offset+firstThunk)
            thunk_offset += struct.calcsize('<L')
        function_strings = firstThunk+thunk_offset
    
    imm.log('[%s] Searching for function names at %X..'%(NAME,function_strings))
    data = pe.get_data(function_strings, (iat.VirtualAddress+iat.Size)-function_strings)
    string_offset = 0
    # store the offset and the string name in a dict
    strings = {}    #k,v pair offset:name
    while True:
        if string_offset >= len(data):
            break
        string = pe.get_string_at_rva(function_strings+string_offset)
        if string:
            if '.dll' not in string.lower():
                strings[function_strings+string_offset] = string
                if DEBUG:
                    imm.log('    %s'%string, address=function_strings+string_offset)
            string_offset+= len(string)
        else:
            string_offset+= 1
    imm.log('[%s] Found %s function names'%(NAME, len(strings)))

    #For each address in IAT, find the function name by either:
    #   o Building a database of Addresses:FunctionNames from your analysis DLLs
    #   o Use imm to determine the function name. This choice is not very accurate - because of imm.
    #       imm does not give us the literal name in case its a forwarder to a function in a different dll
    #       Ex: kernel32.DeleteCriticalSection -> NTDLL.RtlDeleteCriticalSection
    #       imm returns the latter, which cant be used to rebuild the IAT

    # 'address_offset' in the dumped file which points to 'address' for the string
    function_count = 0
    for address_offset, address in addresses.items():
        if int(address) != 0x00000000:
            func = imm.getFunction(address)
            try:
                # name is the name of the function, which is located at string_offset in the dumped file
                # so, we need to write the address of this string (string_offset-2, to compensate for the Hint bytes)
                # to the 'address_offset'
                for string_offset, name in strings.items():
                    # func name is like USER32.GetDC
                    if name in func.getName():
                        tmp = pe.set_dword_at_offset( address_offset, (string_offset-2) )
                        function_count += 1
                        if DEBUG:
                            imm.log('    %2s. Writing %08X [%25s] at %08X [was %08X] - %s'%(function_count, string_offset-2, name, address_offset, address, tmp) )
            except Exception,e:
                imm.log('[%s] Error setting bytes %08X at %08X for %s'%(NAME, (string_offset-2), function_offset, func.getName()),highlight=1)

    pe.write(filename=target)
    imm.log('[%s] Wrote to %s'%(NAME, target))
    pe.close()
	
def main(args):
    imm = immlib.Debugger()
    module = None
    path = "c:\\"
    if 'help' in args:
        usage(imm)
    try:
        opts, args = getopt.getopt(args, "m:p:h::")
    except getopt.GetoptError:
        usage(imm)
        return "Incorrect arguments (Check log window)"
    for o, a in opts:
        if o == "-m":
            module = a
        elif o == "-p":
            path = a
        elif o == "-h":
            usage()
            return '[%s] Done'%NAME
    if not module:
        module = imm.getDebuggedName()
        imm.log('[%s] No module specified. Going to dump "%s"'%(NAME,module))
    if dump(module,path):
        rebuild(path+module, path+module+'_fixed')
    return '[%s] Done'%NAME

