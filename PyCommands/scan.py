#!/usr/bin/env python

#-------------------------------------------------------------------------------
# Module Entropy Scan
# 
# Shows the entropy & MD5 of each section. Useful to randomly track unpacking
# (C) 2010 -2011 Kiran Bandla <kbandla@in2void.com>
#-------------------------------------------------------------------------------


__VERSION__  = '0.01'
NAME        = 'Scan'
DESC        = 'Displays Entropy of modules in memory'
COPYRIGHT   = 'Copyright (C) 2010-2011 Kiran Bandla, <kbandla@in2void.com>'
LICENSE     = 'WTFPL'


import immlib
import math
import pefile
import peutils
import array
import getopt
from hashlib import md5

def usage(imm):
    imm.log(" ")
    imm.log("Entropy checks for modules in memory")
    imm.log("Signature file : .\Data\UserDB.TXT ..")
    imm.log("Options:")
    imm.log("      -m : Scan specific module. Default is the loaded module")
    imm.log("      -a : Scan all modules. Displays entropy table for each module")
    imm.log("      -h : Hardcore mode - Scan whole file. This takes very, very long")
    imm.log(" ")
    return "See log window (Alt-L) for usage .. "

def getEntropy(data):
    """Calculate the entropy of a chunk of data. Form Ero's pefile"""

    if len(data) == 0:
        return 0.0
    
    occurences = array.array('L', [0]*256)
    
    for x in data:
        occurences[ord(x)] += 1
    
    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)
    
    return entropy


def scan_module(name, hardcore=False):
    """
    Scan specifc modules for entropy. Based on BoB's module.
    """
    imm = immlib.Debugger()
    EP_Only = 1
    if hardcore:
            EP_Only = 0
    try:
        Mod  = imm.getModule(name)
        if not Mod:
            raise Exception, "Couldn't find %s .." % name
    except Exception, msg:
        return "Error: %s" % msg

    imm.log(" ")
    imm.log("%s v%s By BoB -> Team PEiD" % (ProgName, ProgVers), focus=1, highlight=1)
    imm.log("Processing \"%s\" .." % name)

    # Load PE File ..
    pe = pefile.PE(name = Mod.getPath())
    imm.log(name)

    # Displays same guessed results as PEiD -> Extra information -> Entropy ..
    e = getEntropy( pe.__data__ )
    if e < 6.0:
        a = "Not packed"
    elif e < 7.0:
        a = "Maybe packed"
    else:  # 7.0 .. 8.0
        a = "Packed"

    # Start processing ..
    imm.log("  o File Entropy : %.2f (%s)" % (e, a))
    imm.log("  o Loading signatures ..")
    imm.setStatusBar("Loading signatures ..")
    # Show now as sigs take a few seconds to load ..
    imm.updateLog()

    # Load signatures ..
    sig_db = peutils.SignatureDatabase('Data/UserDB.TXT')
    imm.log("  o %d total sigs in database .." % (sig_db.signature_count_eponly_true + sig_db.signature_count_eponly_false + sig_db.signature_count_section_start))
    # Display number of signatures to scan ..
    if EP_Only == 1:
        imm.log("  o %d EntryPoint sigs to scan .." % sig_db.signature_count_eponly_true)
        imm.log("  o Scanning Entrypoint ..")
        imm.setStatusBar("Scanning Entrypoint ..")
    else:
        imm.log("  o %d sigs to scan in hardcore mode .." % sig_db.signature_count_eponly_false)
        imm.log("  o Scanning whole file ..")
        imm.setStatusBar("Scanning whole file ..  This may take a few minutes, so go make a coffee ..")
    imm.log(" ")
    # Force update now or user will not know any info until scan finished ..
    # Which can take minutes for a large file scanned with -a option ..
    imm.updateLog()

    # Do the scan, EP only or hardcore mode ..
    ret = sig_db.match( pe, EP_Only == 1 )

    # Display results of scan ..
    imm.log("Result:")
    if not ret:
        return "Nothing found .."

    if EP_Only == 1:
        # If EP detection then result is a string and we know EP address ..
        va = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        addr = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        imm.log("  Found \"%s\" at offset 0x%08X %s" % (ret[0], addr, getSectionInfo(pe, va)), address = va)
        imm.log(" ")
    else:
        # If more than 1 returned detection, then display all possibilities ..
        if len(ret) > 1:
            imm.log("Found %d possible matches .." % len(ret) )
            a = 1
            for (addr, name) in ret:
                va = pe.OPTIONAL_HEADER.ImageBase + rawToRva(pe, addr)
                imm.log('  %02d : \"%s\" at offset 0x%08X %s' % (a, name[0], addr, getSectionInfo(pe, va)), address = va)
                a += 1
            imm.log(" ")
        else:
            # If only 1 detection then display result ..
            for (addr, name) in ret:
                va = pe.OPTIONAL_HEADER.ImageBase + rawToRva(pe, addr)
                imm.log('  Found \"%s\" at offset 0x%08X %s' % (name[0], addr, getSectionInfo(pe, va)), address = va)
                imm.log(" ")
    return '[%s] Done.'%ProgName
    
def main(args):
    imm = immlib.Debugger()
    module = modules = None
    scan_all = False
    default = True
    try:
        opts, args = getopt.getopt(args, "m:a:")
    except getopt.GetoptError:
        usage(imm)
        return "Incorrect arguments (Check log window)"
    for o, a in opts:
        if o == "-m":
            module = a
	    default = False
	elif o == "-a":
	    # scan all modules
	    scan_all = True
	    default = False
    if module:
        if module.split('.')[-1] not in ['exe','sys','dll']:
            module = module+ '.dll'
	modules = [imm.getModule(module)]
    elif default:
	modules = [imm.getModule(imm.getDebuggedName())]
    if scan_all:
	modules = imm.getAllModules()
    table_cols = ["Module", "Section", "Entropy", "Packed?", "MD5"]
    entropies = None
    try:
        entropies = imm.getKnowledge('entropies')
        if not entropies:
            raise Exception
    except:
        entropies = imm.createWindow("Module Entropies", table_cols )
        imm.addKnowledge("entropies", entropies)
    blank_line = ['='*25]*len(table_cols)
    for module in modules:
        pe = pefile.PE(name = module.getPath())
        imm.log('[%s] Analyzing module - %s'%(NAME, module.name))
        for section in pe.sections:
            start= int(module.getBaseAddress()) + int(section.VirtualAddress)
            size = int(section.Misc_VirtualSize) +(int(pe.OPTIONAL_HEADER.SectionAlignment) - int(section.Misc_VirtualSize)%int(pe.OPTIONAL_HEADER.SectionAlignment) )
            data = imm.readMemory(start, size)
            entropy = getEntropy( data )
            md5sum = md5(data).hexdigest()
            if entropy < 6.0:
                a = ""
            elif entropy < 7.0:
                a = ".."
            else:  # 7.0 .. 8.0
                a = "P.A.C.K.E.D"
            log_items = ['%s'%module.getName(),'%s'%section.Name.split('\x00')[0] , '%s'%entropy, '%s'%a, '%s'%md5sum]
            entropies.add(start,log_items)
            imm.updateLog()
        entropies.add(00000000,blank_line)
    return ''
