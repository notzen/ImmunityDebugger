#!/usr/bin/env python

#-------------------------------------------------------------------------------
# Process Dump Utility for Immunity Debugger 1.83
# (C) 2011 Kiran Bandla <kbandla@in2void.com>
#-------------------------------------------------------------------------------


__VERSION__  = '0.01'
NAME        = 'Dump'
DESC        = 'Dump process to disk'
COPYRIGHT   = '(C) 2011 Kiran Bandla, <kbandla@in2void.com>'
LICENSE     = 'WTFPL'

import immlib
import pefile
import getopt
import struct
from ctypes import *
from pelib import *

DEBUG = False

def usage(imm):
    imm.log(" ")
    imm.log("PE Dumper [%s] by kbandla" % (NAME), focus=1, highlight=1)
    imm.log("This script will dump a module to disk.")
    imm.log("Options:")
    imm.log("      -m : module name to dump. Default is the loaded module")
    imm.log("      -p : path of dump file. Default is c:\sample.exe")
    imm.log(" ")
    return "See log window (Alt-L) for usage .. "

def dump(name, path):
    """
    Dump a process to disk, and fix some section parameters
    """
    imm = immlib.Debugger()
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
            imm.log('Section #%s '%(i))
            imm.log('='*10)
            imm.log('PointerToRawData = %s'%(section.PointerToRawData))
            imm.log('VirtualAddress = %s'%(section.VirtualAddress))
            imm.log('SizeOfRawData = %s'%(section.SizeOfRawData))
            imm.log('VirtualSize = %s'%(section.Misc_VirtualSize))
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
    iat_data = pe.get_data(iat.VirtualAddress, iat.Size)
    imm.log('[%s] Potential IAT found at %08X. Size: %08X'%(NAME, iat.VirtualAddress, iat.Size))
    offset = 0
    function_strings = 0
    addresses = {}
    while True:
        im = ImportDescriptor()
        data = iat_data[offset:offset+im.getSize()]
        if data == '\x00'*20:
            break
        try:
            im.get(data)
        except Exception,e:
            imm.log('No IAT Found at the location. Quitting.')
            return 'Error. See Log'
        offset+=im.getSize()
        dll_name = str()
        i = 0
        while True:
            char_ = pe.get_data(im.Name+i,1)
            if  char_!= '\x00':
                dll_name += char_
                i = i+1
            else:
                break
        if DEBUG:
            imm.log('[%s] Found %s at %08x'%(NAME, dll_name, im.Name))
        firstThunk = int(im.FirstThunk)
        thunk_offset = 0
        
        while True:
            data = pe.get_data(firstThunk+thunk_offset, struct.calcsize('<L'))
            address = struct.unpack('<L', data)
            addresses[thunk_offset+firstThunk] = address[0]
            if DEBUG and (address[0]!=0x00000000):
                func = imm.getFunction(address[0])
                imm.log('%08x [was %s]'%(address[0],func.getName()),address=thunk_offset+firstThunk)
            if address[0] == 0x00000000:
                thunk_offset += struct.calcsize('<L')
                break
            else:
                thunk_offset += struct.calcsize('<L')
        function_strings = firstThunk+thunk_offset
    
    imm.log('[%s] Searching for function names at %x..'%(NAME,function_strings))
    data = pe.get_data(function_strings, (iat.VirtualAddress+iat.Size)-function_strings)
    string_offset = 0
    strings = {}    #k,v pair offset:name
    while True:
        if string_offset>=len(data):
            break
        string = pe.get_string_at_rva(function_strings+string_offset)
        if string:
            strings[function_strings+string_offset] = string
            if DEBUG:
                imm.log('%s'%string, address=function_strings+string_offset)
            string_offset+= len(string)
        else:
            string_offset+= 1
    imm.log('[%s] Found %s function names'%(NAME, len(strings)))

    #For each address in IAT, find the function name by either:
    #   o Building a database of Addresses:FunctionNames from your analysis DLLs
    #   o Use imm to determine the function name. This choice is not very accurate - becuase of imm.

    for offset, address in addresses.items():
        if int(address) != 0x00000000:
            func = imm.getFunction(address)
            try:
                for string_offset, name in strings.items():
                    if name in func.getName():
                        if DEBUG:
                            imm.log('Writing %08X [%25s] at %08X [was %08X]'%(string_offset, name, offset, address) )
                        pe.set_dword_at_offset( offset, (string_offset-2) )
            except Exception,e:
                imm.log('[%s] Error setting bytes %08X at %08X for %s'%(NAME, (string_offset-2), offset, func.getName()),highlight=1)
    pe.write(filename=target)
    imm.log('[%s] Wrote to %s'%(NAME, target))
	
def main(args):
    imm = immlib.Debugger()
    module = None
    path = 'c:\sample.exe'
    if 'help' in args:
        usage(imm)
    try:
        opts, args = getopt.getopt(args, "mp")
    except getopt.GetoptError:
        usage(imm)
        return "Incorrect arguments (Check log window)"
    for o, a in opts:
        if o == "-m":
            module = a
        elif o == "-p":
            path = a
    if not module:
        module = imm.getDebuggedName()
        imm.log('[%s] No module specified. Going to dump "%s"'%(NAME,module))
    dump(module,path)
    rebuild(path)
    return '[%s] Done'%NAME

