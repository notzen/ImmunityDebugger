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
    imm.log('[%s] Wrote %s bytes to %s'%(NAME,size, path))
    del(pe)
    return True

def rebuild(filepath):
    """
    ReBuild IAT
    """
    imm = immlib.Debugger()
    pe = pefile.PE(filepath)
    iat = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
    iat_data = pe.get_data(iat.VirtualAddress, iat.Size)
    offset = 0
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
        imm.log('%08x [%s]'%(im.Name,dll_name))
        firstThunk = int(im.FirstThunk)
        thunk_offset = 0 
        while True:
            data = pe.get_data(firstThunk+thunk_offset, struct.calcsize('<L'))
            address = struct.unpack('<L', data)
            if address[0] == 0x00000000:
                break
            else:
                thunk_offset += struct.calcsize('<L')
            func = imm.getFunction(address[0])
            #imm.log('%08x %s'%(address[0],func.getName()))
        
	
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
