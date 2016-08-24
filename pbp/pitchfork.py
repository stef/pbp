#!/usr/bin/env python

# #!#!#!#!#!#!#!#!#!#!#!#!#!#!#
# need to call init()
# before using
# #!#!#!#!#!#!#!#!#!#!#!#!#!#!#

import sys
import time
import usb.core
import usb.util
import pysodium as nacl
from utils import inputfd, outputfd, b85encode, b85decode
from struct import unpack

idVendor=0x0483
idProduct=0x5740
DEBUG = False

if DEBUG:
    import os
    os.environ['PYUSB_DEBUG_LEVEL'] = 'warning' # 'debug'
    os.environ['PYUSB_DEBUG'] = 'warning' # 'debug'

# PITCHFORK Consts
EKID_SIZE=31
PEER_NAME_MAX=32

USB_CRYPTO_EP_CTRL_IN = 0x01
USB_CRYPTO_EP_DATA_IN = 0x02
USB_CRYPTO_EP_CTRL_OUT = 0x81
USB_CRYPTO_EP_DATA_OUT = 0x82

USB_CRYPTO_CMD_ENCRYPT = chr(0)
USB_CRYPTO_CMD_DECRYPT = chr(1)
USB_CRYPTO_CMD_SIGN = chr(2)
USB_CRYPTO_CMD_VERIFY = chr(3)
USB_CRYPTO_CMD_ECDH_START = chr(4)
USB_CRYPTO_CMD_ECDH_RESPOND = chr(5)
USB_CRYPTO_CMD_ECDH_END = chr(6)
USB_CRYPTO_CMD_LIST_KEYS = chr(7)
USB_CRYPTO_CMD_RNG = chr(8)
USB_CRYPTO_CMD_STOP = chr(9)
USB_CRYPTO_CMD_STORAGE = chr(10)

# USB endpoint cache
eps={}

#####  crypto ops  #####

def encrypt(peer, infile=None, outfile=None):
    if len(peer)>PEER_NAME_MAX:
        raise ValueError

    fd = inputfd(infile)
    outfd = outputfd(outfile or infile+'.pbp' if infile else '-')
    reset()

    eps[USB_CRYPTO_EP_CTRL_IN].write(USB_CRYPTO_CMD_ENCRYPT+peer, timeout=0)
    tmp = read_ctrl(timeout=0)
    if(tmp and tmp.startswith('err: ')):
       raise ValueError(tmp)
    # needs to return keyid read it here
    keyid = ''.join([chr(x) for x in eps[USB_CRYPTO_EP_CTRL_OUT].read(EKID_SIZE, timeout=0)])
    if(keyid.startswith('err: ')):
        raise ValueError(keyid)
    if len(keyid)<EKID_SIZE:
        print len(keyid),EKID_SIZE
        print repr(keyid)
        raise ValueError
    pkt = fd.read(32768)
    #if len(pkt)>0:
    #    outfd.write(keyid)
    while pkt:
        wrote = eps[USB_CRYPTO_EP_DATA_IN].write(pkt, timeout=0)
        if (wrote<32768 and not (wrote&0x3f)):
            eps[USB_CRYPTO_EP_DATA_IN].write(None, timeout=0)
        outfd.write(''.join([chr(x) for x in eps[USB_CRYPTO_EP_DATA_OUT].read(wrote+40, timeout=0)]))
        pkt = fd.read(32768)
    if(len(pkt)==32768):
        eps[USB_CRYPTO_EP_DATA_IN].write(None, timeout=0)

    reset()

    if fd != sys.stdin: fd.close()
    if outfd != sys.stdout: outfd.close()
    return keyid

def decrypt(keyid, infile=None, outfile=None):
    keyid=b85decode(keyid)
    if(len(keyid)!=EKID_SIZE):
        raise ValueError

    fd = inputfd(infile)
    outfd = outputfd(outfile or infile+'.pbp' if infile else '-')

    reset()

    eps[USB_CRYPTO_EP_CTRL_IN].write(USB_CRYPTO_CMD_DECRYPT+keyid, timeout=0)
    tmp = read_ctrl(timeout=0)
    if(tmp and tmp.startswith('err: ')):
       raise ValueError(tmp)
    tmp = read_ctrl(timeout=0)

    pkt = fd.read(32808)
    if(tmp and tmp!="go"):
       raise ValueError(tmp)
    #if len(pkt)>0:
    #    outfd.write(keyid)
    while pkt:
        wrote = eps[USB_CRYPTO_EP_DATA_IN].write(pkt, timeout=0)
        if (wrote<32808 and not (wrote&0x3f)):
            eps[USB_CRYPTO_EP_DATA_IN].write(None, timeout=0)
        tmp = read_ctrl(timeout=50)
        if(tmp and tmp.startswith('err: ')):
            raise ValueError(tmp)
        outfd.write(''.join([chr(x) for x in eps[USB_CRYPTO_EP_DATA_OUT].read(wrote-40, timeout=0)]))
        pkt = fd.read(32808)
    if(len(pkt)==32808):
        eps[USB_CRYPTO_EP_DATA_IN].write(None, timeout=0)

    reset()
    if fd != sys.stdin: fd.close()
    if outfd != sys.stdout: outfd.close()

def sign(peer, infile=None, outfile=None):
    if len(peer)>PEER_NAME_MAX:
        raise ValueError

    fd = inputfd(infile)
    outfd = outputfd(outfile)

    reset()
    written=0

    eps[USB_CRYPTO_EP_CTRL_IN].write(USB_CRYPTO_CMD_SIGN+peer, timeout=0)
    tmp = read_ctrl(timeout=0)
    if(tmp and tmp.startswith('err: ')):
       raise ValueError(tmp)
    # needs to return keyid read it here
    keyid = ''.join([chr(x) for x in eps[USB_CRYPTO_EP_CTRL_OUT].read(EKID_SIZE, timeout=0)])
    if(keyid.startswith('err: ')):
       return
    if len(keyid)<EKID_SIZE:
        return
    pkt = fd.read(32768)
    tmp = read_ctrl(timeout=0)
    if(tmp and tmp!="go"):
       raise ValueError(tmp)
    #if len(pkt)>0:
    #    outfd.write(keyid)
    while pkt:
        written+=eps[USB_CRYPTO_EP_DATA_IN].write(pkt, timeout=0)
        pkt = fd.read(32768)
        if outfile: outfd.write(pkt)
    if(written%64==0):
        eps[USB_CRYPTO_EP_DATA_IN].write(None, timeout=0)
    read_ctrl()
    res = eps[USB_CRYPTO_EP_DATA_OUT].read(nacl.crypto_generichash_BYTES, timeout=0)

    read_ctrl()
    reset()
    if fd != sys.stdin: fd.close()
    if outfd != sys.stdout: outfd.close()
    return ''.join([chr(x) for x in res]), keyid

def verify(sign, keyid, infile=None, outfile=None):
    keyid=b85decode(keyid)
    sign=b85decode(sign)
    if(len(keyid)!=EKID_SIZE or len(sign)!= nacl.crypto_generichash_BYTES):
        print len(keyid), EKID_SIZE, repr(keyid)
        print len(sign), 32, repr(sign)
        raise ValueError

    fd = inputfd(infile)
    outfd = outputfd(outfile) if outfile else None

    reset()
    written=0

    eps[USB_CRYPTO_EP_CTRL_IN].write("%s%s%s" % (USB_CRYPTO_CMD_VERIFY,sign,keyid), timeout=0)
    tmp=read_ctrl(timeout=0)
    if(tmp and tmp.startswith('err: ')):
       return
    tmp = read_ctrl(timeout=0)
    if(tmp and tmp!="go"):
       raise ValueError(tmp)
    pkt = fd.read(32768)
    #if len(pkt)>0:
    #    outfd.write(keyid)
    while pkt:
        written+=eps[USB_CRYPTO_EP_DATA_IN].write(pkt, timeout=0)
        if outfd: outfd.write(pkt)
        pkt = fd.read(32768)
    if(written%64==0):
        eps[USB_CRYPTO_EP_DATA_IN].write(None, timeout=0)
    read_ctrl()
    res = eps[USB_CRYPTO_EP_DATA_OUT].read(1, timeout=0)
    read_ctrl()
    reset()
    if fd != sys.stdin: fd.close()
    if outfd and outfd != sys.stdout: outfd.close()
    return res[0]

def start_ecdh(name):
    flush(USB_CRYPTO_EP_DATA_OUT)
    eps[USB_CRYPTO_EP_CTRL_IN].write(USB_CRYPTO_CMD_ECDH_START+name, timeout=0)
    tmp = read_ctrl(timeout=0)
    if(tmp and tmp.startswith('err: ')):
       raise ValueError(tmp)
    resp=eps[USB_CRYPTO_EP_DATA_OUT].read(64, timeout=0)
    reset()
    resp = ''.join([chr(x) for x in resp])
    return (resp[:16], resp[16:])

def resp_ecdh(pub, name):
    pub=b85decode(pub)
    flush(USB_CRYPTO_EP_DATA_OUT)
    eps[USB_CRYPTO_EP_CTRL_IN].write(USB_CRYPTO_CMD_ECDH_RESPOND+pub+name, timeout=0)
    tmp = read_ctrl(timeout=0)
    if(tmp and tmp.startswith('err: ')):
       raise ValueError(tmp)
    resp=eps[USB_CRYPTO_EP_DATA_OUT].read(64, timeout=0)
    reset()
    resp = ''.join([chr(x) for x in resp])
    return (resp[16:], resp[:16])

def end_ecdh(pub, keyid):
    pub=b85decode(pub)
    keyid=b85decode(keyid)
    flush(USB_CRYPTO_EP_DATA_OUT)
    eps[USB_CRYPTO_EP_CTRL_IN].write(USB_CRYPTO_CMD_ECDH_END+pub+keyid, timeout=0)
    tmp = read_ctrl(timeout=0)
    if(tmp and tmp.startswith('err: ')):
       raise ValueError(tmp)
    resp=eps[USB_CRYPTO_EP_DATA_OUT].read(64, timeout=0)
    reset()
    return ''.join([chr(x) for x in resp])

def rng(size, outfile=None):
    outfd = outputfd(outfile or '-')
    reset()
    read = 0
    res = ''
    eps[USB_CRYPTO_EP_CTRL_IN].write(USB_CRYPTO_CMD_RNG)
    while(read<size):
        res=eps[USB_CRYPTO_EP_DATA_OUT].read(32768 if size - read > 32768 else size -read)
        outfd.write(''.join([chr(x) for x in res]))
        read += len(res)

    eps[USB_CRYPTO_EP_CTRL_IN].write(USB_CRYPTO_CMD_STOP)
    read_ctrl()
    reset()

def listkeys(peer):
    reset()
    eps[USB_CRYPTO_EP_CTRL_IN].write(USB_CRYPTO_CMD_LIST_KEYS+(peer or ''), timeout=0)
    tmp = read_ctrl(timeout=0)
    if(tmp and tmp.startswith('err: ')):
       raise ValueError(tmp)
    try:
        buf=''.join([chr(x) for x in eps[USB_CRYPTO_EP_DATA_OUT].read(32768, timeout=0)])
    except usb.core.USBError:
        return
    reset()
    if len(buf)<8:
        return
    i=0
    keys={}
    keycnt = 0
    dups = 0
    while(i<len(buf)-8):
        name = buf[i:buf[i:].find('\0')+i]
        i+=len(name)+1
        keyid = buf[i:i+16]
        i+=16
        if not name in keys:
            keys[name]=[]
        if keyid not in keys[name]:
            keys[name].append(keyid)
        else:
            dups+=1
        keycnt+=1

    stats={'deleted': unpack('H',buf[-8:-6])[0],
           'corrupt': unpack('H',buf[-6:-4])[0],
           'noname': unpack('H',buf[-4:-2])[0],
           'size': unpack('H',buf[-2:])[0],
           'duplicates': dups,
           'key count': keycnt}
    return keys, stats

#####  support ops  #####
def init():
    dev = usb.core.find(idVendor=idVendor, idProduct=idProduct)
    cfg = dev.get_active_configuration()
    interface_number = cfg[(0,0)].bInterfaceNumber
    intf = usb.util.find_descriptor(cfg, bInterfaceNumber = interface_number)
    for ep in intf:
        eps[ep.bEndpointAddress]=ep

def reset():
    eps[USB_CRYPTO_EP_CTRL_IN].write(USB_CRYPTO_CMD_STOP)
    flush(USB_CRYPTO_EP_DATA_OUT)
    flush(USB_CRYPTO_EP_CTRL_OUT)

def flush(ep, quiet=True):
    while(True):
        try:
            tmp = eps[ep].read(64, timeout=10)
        except usb.core.USBError:
            break
        if not quiet: print '>', len(tmp), repr(''.join([chr(x) for x in tmp]))

def read_ctrl(size=32768, timeout=10):
    try:
        tmp = eps[USB_CRYPTO_EP_CTRL_OUT].read(size, timeout=timeout)
    except usb.core.USBError:
        return
    return ''.join([chr(x) for x in tmp])

def storage_stats(stats, keys):
    print 'keys: noname =', stats['noname'],
    print 'corrupt =',  stats['corrupt'],
    print 'duplicates =',  stats['duplicates'],
    print 'deleted =', stats['deleted'],
    print 'total =', stats['key count']
    size = stats['size']
    reclaimable = size - (64                                           # userdata
                          + len(''.join(keys.keys())) + (35*len(keys)) # name mapping records
                          + 81*stats['key count'])                     # sizeof(seedrecord) * keys
    purge = size - (64                                           # userdata
                    + len(''.join(keys.keys())) + (35*len(keys)) # name mapping records
                    + 81*len(keys))                              # sizeof(seedrecord) * keys
    print 'storage full =', (size*100)>>16, '%', size, 'bytes,',
    print 'reclaimable =', (reclaimable*100)/size, '%', reclaimable, 'bytes,',
    print 'purgable =', (purge*100)/size, '%', purge, 'bytes'

def print_keys(keys):
    for n,i in keys.items():
        print n
        print '\t%s' % '\n\t'.join([b85encode(x) for x in i][-3:])
        if len(i)>3:
            print '   has', len(i)-3, 'more keys...'
        print

######  software archaeological artifacts  #######

init()

if __name__ == '__main__':
    #pass
    #print flush(USB_CRYPTO_EP_CTRL_IN, False)
    #print flush(USB_CRYPTO_EP_CTRL_OUT, False)
    #print flush(USB_CRYPTO_EP_DAT_IN, False)
    #print flush(USB_CRYPTO_EP_DATA_OUT, False)
    #print repr(read_ctrl())
    #rng(10, '-')
    keys, stats = listkeys('')
    print keys, stats
    print storage_stats(stats, keys)

    #print >>sys.stderr, b85encode(encrypt('test user a'))
    #encrypt('test user a')
    # todo test decrypt/encrypt falling on buffer boundary
    #decrypt(b85decode('5wo?6Ppot4Aa0VC_{P!G'))
    #tmp = sign('test user a')
    #if tmp:
    #    print b85encode(tmp[0])
    #    print b85encode(tmp[1])
    #print verify(b85decode('m$|4hT<$PhUe9zt4c-y1xd?r%2Ki1B+}_Nfi6Z`j'),
    #             b85decode('5wo?6Ppot4Aa0VC_{P!G'))
