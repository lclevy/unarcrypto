# unarcrypto.py 
# crypto experiments for .zip, .7z and .rar archives using Python 3.3 and PyCryptodome
# supported archive formats: 
#   zip (deflate, aes128 and aes256), 7zip (store, data encryption, headers encryption)
#   rar3 and rar5 (store, data encryption, headers encryption) 
# copyright Laurent Clevy (@lorenzo2472). December 2016
# license is GPLv3

#python 3 to 2 compatibility
from __future__ import print_function

import sys
from struct import unpack, pack, Struct
from binascii import hexlify, unhexlify
import hmac
from hashlib import sha1, sha256
from zlib import decompress, crc32
from optparse import OptionParser

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import Counter
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES

AES_BLOCK_LEN = 16 #used by Rar3 for padding

#switching from PyCrypto 2.6.1 (no more supported) to PyCryptodome 
#tested with Python 3.6.7 and PyCryptodome 3.7.0
#easy_install pycryptodome
#using pip I had "ModuleNotFoundError: No module named 'Crypto.Protocol.KDF'"
# https://github.com/Legrandin/pycryptodome/issues/235
#pip install -r requirement.txt should work when fixed

parser = OptionParser()
parser.add_option("-p", "--pw", dest="password", help="password")
parser.add_option("-s", "--sha1sum", dest="sha1sum", help="sha1sum")
parser.add_option("-v", "--verbose", type='int', dest="verbose", help="verbose", default=0)

(options, args) = parser.parse_args()

if(len(args) != 1):
  parser.print_help()
  exit(1)

try:
  f=open(args[0],'rb')
  data = f.read()
  f.close()

except IOError:
  print("Couldn't read the file", args[0])
  exit(1)


password = options.password
print('password=',password)

#for Zip with AES
class Zip:
  EOCENTRAL_MAGIC = b'PK\x05\x06'
  LOCAL_MAGIC = b'PK\x03\x04'
  CENTRAL_DIR_MAGIC = b'PK\x01\x02'
  S_ENDOFCENTRAL_REC = Struct('<LHHHHLLH') 
  S_CENTRAL_REC = Struct('<LHHHHHHLLLHHHHHLL')
  S_LOCAL_REC = Struct('<LHHHHHLLLHH')
  S_AES_EXTRA = Struct('<HHHHBH')
  AES_ENCRYPTED = 99
  
  def __init__(self, data, endCentralDir):
    #print('%x' % endCentralDir)
    self.eoCentralOffset = endCentralDir
    self.data = data
    
  def parse(self):
    newCentralOffset = self.parseEndOfCentralDir()
    while newCentralOffset < self.eoCentralOffset:
      localHeaderOffset, entryLen, centralCrc =  self.centralDirHeader( newCentralOffset )
      compression, compressed, uncompressed, filenameLen, extraLen, name, extra, method, encryptionStrength, crc = self.readLocalFileHeader( localHeaderOffset )
      if compression==Zip.AES_ENCRYPTED:
        offset = localHeaderOffset+Zip.S_LOCAL_REC.size+filenameLen+extraLen
        decompCrc = self.encryptedFile( offset, compressed, encryptionStrength )
        print(' CRC on decrypted, then decompressed data is OK ?', centralCrc==decompCrc)
      else:
        decompressed = decompress( self.data[localHeaderOffset+30+filenameLen+extraLen:], -15 ) 
        print(' CRC on decompressed data is OK ?',crc32(decompressed)==crc)
      newCentralOffset += entryLen
  
  def parseEndOfCentralDir(self):
    sign, v, v, v, v, v, self.centralDirOffset, v = Zip.S_ENDOFCENTRAL_REC.unpack_from(self.data, self.eoCentralOffset)
    return self.centralDirOffset
  
  def encryptedFile(self, offset, compressedLength, encryptionStrength): #compressed length is including salt, password verif, and authcode...
    """
    http://www.winzip.com/win/en/aes_info.html#auth-faq

    III. Encrypted file storage format (total = compressed size)

    for AES-256
    16 bytes   salt                      
     2 bytes   password verification value
               encrypted file
    10 bytes   authentication code 

    from http://www.gladman.me.uk/cryptography_technology/fileencrypt/

    keys = pbkdf2( password, salt, sha1, iterations=1000, keylen=32*2+2), 32 is key size for AES 256
    keys = [32 bytes aes key, 32 bytes hmac-sha1 key, 2 bytes password verification value]
    first 32 key is for AES 256 CTR, with initial_value=1, little_endian=True
    second 32 key is for hmac-sha1 on encrypted content. First 80bits of hmac is authentication code (10 bytes)
    """
    AUTH_CODE_LEN = 10
    PASSWD_VERIF_LEN = 2
    PBKDF2_ITER = 1000
    lenParams = { 1:[8, 16], 2:[12,24], 3:[ 16, 32] } # [ salt len, key len ], WinZip v21 can create aes128 (1) and 256 (3) ...
    if 1 <= encryptionStrength <=3:
      saltLen, keyLen = lenParams[encryptionStrength]
    else:
      print('unsupported encryptionStrength')
    fileCompressedLen = compressedLength - (saltLen+PASSWD_VERIF_LEN+AUTH_CODE_LEN)
    salt = self.data[ offset: offset+saltLen] 
    passwdVerification = self.data[ offset+saltLen : offset+saltLen+PASSWD_VERIF_LEN ]
    fileData = self.data[ offset+saltLen+PASSWD_VERIF_LEN : offset+compressedLength-AUTH_CODE_LEN ]
    authCode = self.data[ offset+compressedLength-AUTH_CODE_LEN : offset+compressedLength ]
    print('  salt', hexlify(salt), 'pv', hexlify(passwdVerification), 'auth code', hexlify(authCode) )
    #default PBKDF2 algo is hmac-sha1, https://www.dlitz.net/software/pycrypto/api/2.6/Crypto.Protocol.KDF-module.html
    keys = PBKDF2(password, salt, dkLen=keyLen*2+PASSWD_VERIF_LEN, count=PBKDF2_ITER) #PyCrypto
    #pbkdf2_hmac('sha1',password,salt,ITER,dklen=keyLen*2+PASSWD_VERIF_LEN)   #should be the syntax for python 3.4
    
    #test vector in http://www.gladman.me.uk/cryptography_technology/fileencrypt/, pwd2key.c, line 124 == b'd1daa78615f287e6a1c8b120d7062a49'
    print('   passwd verif OK ?', keys[-2:]==passwdVerification, end=',')
    myhmac = hmac.new( keys[keyLen:keyLen*2], fileData, sha1).digest()  
    print('   authCode OK ?',myhmac[:10]==authCode)
    NUM_COUNTER_BITS=128
    ctr = Counter.new( nbits=NUM_COUNTER_BITS, initial_value=1,  little_endian=True )
    cleartext = AES.new( keys[:keyLen], AES.MODE_CTR, counter=ctr ).decrypt(fileData)
    print('   aes key',hexlify(keys[:keyLen]))
    # https://docs.python.org/3/library/zlib.html#decompress-wbits, "The input must be a raw stream with no header or trailer"
    decompressed = decompress(cleartext, -15)  
    if options.sha1sum:
      print ('sha1 decompressed OK ? ',sha1(decompressed).hexdigest()==options.sha1sum)
    return crc32(decompressed)

  def readLocalFileHeader(self, offset):
    sign, version, flags, compression, time, date, crc, compressed, uncompressed, filenameLen, extraLen = Zip.S_LOCAL_REC.unpack_from(self.data, offset)
    if pack('<I',sign)!=Zip.LOCAL_MAGIC:
      print('sign!=ZIP.LOCAL_MAGIC')
    name = self.data[ Zip.S_LOCAL_REC.size: Zip.S_LOCAL_REC.size+filenameLen ]
    extraOffset = Zip.S_LOCAL_REC.size+filenameLen
    extra = self.data[ extraOffset: extraOffset+extraLen ]
    print( '0x%06x: local entry:'%offset, pack('<I',sign), 'name ',name,'size',uncompressed,'compressed',compressed,'method',compression, 'extraLen',extraLen, 'crc %x' % crc)
    if extraLen>0:
      #http://www.winzip.com/win/en/aes_info.htm#zip-format
      extraHeader, v, vendor, vendorId, encryptionStrength, method = Zip.S_AES_EXTRA.unpack_from(extra)
      print(' extra: %x' % extraHeader,'vendor', vendor, 'vendorId %c%c' % (vendorId&0xff,vendorId>>8), 'strength', encryptionStrength, 'method', method)
    else:
      method = encryptionStrength = 0  
    return compression, compressed, uncompressed, filenameLen, extraLen, name, extra, method, encryptionStrength, crc

  def centralDirHeader(self, offset):
    sign, ver_made, ver_needed, flags, compression, time, date, crc, compressed, uncompressed, nameLen, extraLen, commentLen, diskNb, intAttr, extAttr, localHeaderOffset = Zip.S_CENTRAL_REC.unpack_from(data, offset)
    if pack('<I',sign)!=Zip.CENTRAL_DIR_MAGIC:
      print('sign!=CENTRAL_DIR_MAGIC')
    name = self.data[ offset+Zip.S_CENTRAL_REC.size: offset+Zip.S_CENTRAL_REC.size+nameLen ]
    print( '0x%06x: central entry:'%offset, pack('<I',sign), 'name',name,'compressed',compressed,'uncompressed',uncompressed,'compression',compression, 'localHeader',localHeaderOffset)
    return localHeaderOffset, Zip.S_CENTRAL_REC.size+nameLen+extraLen+commentLen, crc
 

# minimal RAR 3.x implementation to check password key derivation, decryption and encrypted headers
class Rar3:
  HEADER_MAGIC = b'Rar!\x1A\x07\x00' #crc 0x6152 (2 bytes), type 0x72(1 byte), flags (0x1a21), size (0x0007)
  FILE_HEADER_WITH_PASSWD = 0x0004
  FILE_HEADER_HAS_SALT    = 0x0400
  FILE_HEADER_HAS_HIGH    = 0x0100
  FILE_HEADER_HAS_EXT_TIME = 0x1000
  FILE_HEADER_HAS_ADD_SIZE = 0x8000
  BLOCK_HEADER_ISENCRYPTED = 0x0080
  METHOD_STORING = 0x30
  SALT_SIZE = 8
  HEADER_TYPE_MARKER = 0x72
  HEADER_TYPE_ARCHIVE = 0x73
  HEADER_TYPE_FILE = 0x74
  HEADER_TYPE_COMMENT = 0x75
  HEADER_TYPE_TERMINATOR = 0x7b
  headerType = { HEADER_TYPE_MARKER:"marker", HEADER_TYPE_ARCHIVE:"archive", HEADER_TYPE_FILE:"file", HEADER_TYPE_COMMENT:"comment", HEADER_TYPE_TERMINATOR:"terminator" }
  
  # https://github.com/php/pecl-file_formats-rar/blob/master/technote.txt  
  # HEAD_CRC (H), HEAD_TYPE (B), HEAD_FLAGS (H), HEAD_SIZE
  S_BLOCK_HDR = Struct('<HBHH')  

  # PACK_SIZE (L), UNP_SIZE (L), HOST_OS (B), FILE_CRC (L), FTIME (L), UNP_VER (B), METHOD (B), NAME_SIZE (H), ATTR (L), 
  # optionnal : HIGH_PACK_SIZE (L), HIGH_UNP_SIZE (L)
  # FILE_NAME, SALT (8B), EXT_TIME (variable, assuming 5)
  S_FILE_HDR = Struct('<LLBLLBBHL') 
  
  def __init__(self, size):  
    self.currentOffset = 0
    self.dataLen = size
    self.depth = 0
    
  def keyDerivation(salt, password):
    #key derivation algo for RAR3.0
    """expandedPw = bytearray( len(password)*2 )
    iv = bytearray( 16 )
    key = bytearray( 16 )
    for i in range(len(password)):
      expandedPw[ i*2 ] = ord( password[ i ] )
    expandedPw += salt
    #based on unrar source code and p7zip, RarAes.cpp
    hash = sha1()
    numRounds = 1<<18
    for round in range(numRounds):
      hash.update( expandedPw )
      c = pack('<L',round)
      hash.update( c[:3] )
      if (round % (numRounds/16)) == 0:
        hashTmp = hash
        d1 = hashTmp.digest()
        iv[round // (numRounds // 16)] = d1[4 * 4 + 3];
    d2 = hash.digest()
    for i in range(4):
      for j in range(4):
        key[i * 4 + j] = d2[i * 4 + 3 - j]"""
    #rar3_s2k from rarfile 2.8 by Marko Kreen <markokr@gmail.com> is much more elegant !
    #2017/01/03: just seen (after my Rar5 code is working) that rarfile 3.0 (from 2016/12/27) now supports RAR5 files!
    #https://pypi.python.org/pypi/rarfile/
    seed = password.encode('utf-16le') + salt
    iv = b''
    hash = sha1()
    for i in range(16):
      for j in range(0x4000):
        cnt = Struct('<L').pack(i*0x4000 + j)
        hash.update(seed + cnt[:3])
        if j == 0:
          iv += hash.digest()[19:20]
    key_be = hash.digest()[:16]
    key_le = pack("<LLLL", *unpack(">LLLL", key_be))    
    return iv, key_le    

  def decryptFile(self, salt, encrypted):
    iv, key = Rar3.keyDerivation( salt, password )
    if options.verbose > 1:
      print(self.depth*'  '+'iv', hexlify(iv), 'key', hexlify(key)) 
    return AES.new( bytes(key), AES.MODE_CBC, bytes(iv) ).decrypt( encrypted )
    
  def parseMarkerBlock(self, data):
    return Rar3.S_BLOCK_HDR.unpack_from(data)
    
  def parseFileBlock(self, data, size, flags, addsize):
    packSize, unpSize, HOST_OS, fileCrc, FTIME, UNP_VER, method, nameSize, ATTR = Rar3.S_FILE_HDR.unpack_from(data)

    if flags & Rar3.FILE_HEADER_HAS_HIGH:
      high = 8
    else:
      high = 0      
    filename = data[Rar3.S_FILE_HDR.size+high:Rar3.S_FILE_HDR.size+high+nameSize]
    if options.verbose > 1:
      print(self.depth*'  '+'pack_size',packSize,'unp_size',unpSize, 'file_crc %x' % fileCrc, 'method 0x%x, ' % method, 'name_size',nameSize, filename, 'addsize %d' % addsize, 'high', high)
    if flags & Rar3.FILE_HEADER_WITH_PASSWD: 
      print(self.depth*'  '+'has password')
    if flags & Rar3.FILE_HEADER_HAS_EXT_TIME:
      print(self.depth*'  '+'has ext_time')
      extTime = 5 # assume ==5, for exact computation, see unrar source code, arcread.cpp, line 365 or look for 'LHD_EXTTIME'
    else:
      extTime = 0     

    if flags & Rar3.FILE_HEADER_HAS_SALT: 
      if password is None:
        print(self.depth*'  '+'error -p option is required')
        exit()
      #http://blog.zorinaq.com/brute-forcing-rar-archives-encrypted-with-the-hp-option/
      #http://anrieff.net/ucbench/technical_qna.html
      saltOffset = Rar3.S_FILE_HDR.size+high+nameSize
      salt = data[ saltOffset : saltOffset+Rar3.SALT_SIZE ]   
      print(self.depth*'  '+'file salt',hexlify(salt))  
      dataOffset = saltOffset+Rar3.SALT_SIZE+extTime
      encrypted = data[ dataOffset : dataOffset+packSize+addsize ] 
      return packSize, unpSize, encrypted, method, fileCrc, salt
    else:
      print(self.depth*'  '+'no salt')      
      dataOffset = Rar3.S_FILE_HDR.size+high+nameSize+extTime
      filedata = data[ dataOffset: dataOffset+packSize ]
      #print(filedata)
      return packSize, unpSize, filedata, method, fileCrc, None
  
  def decryptHeader(iv, key, data):
    decrypted = AES.new( bytes(key), AES.MODE_CBC, bytes(iv) ).decrypt( data )
    return decrypted
  
  def parse(self, data):
    #http://www.forensicswiki.org/w/images/5/5b/RARFileStructure.txt
    headersEncrypted = False 
    paddingLen = 0

    while self.currentOffset < len(data):
      #print('self.currentOffset %x' % self.currentOffset)
      if not headersEncrypted:
        headCrc, headType, headFlags, headSize = self.parseMarkerBlock( data[self.currentOffset:] )
        if headType != Rar3.HEADER_TYPE_FILE:
          addSize = 0
          if headFlags & Rar3.FILE_HEADER_HAS_ADD_SIZE:
             addSize = unpack('<L',data[Rar3.S_RAR3_BLOCK_HDR.size:Rar3.S_RAR3_BLOCK_HDR.size+4])[0]
        
      else: #headersEncrypted

        salt = data[self.currentOffset:self.currentOffset+Rar3.SALT_SIZE]
        print(self.depth*'  '+'header salt',hexlify(salt))
        iv, key = Rar3.keyDerivation( salt, password )
        print(self.depth*'  '+'iv',hexlify(iv),'key',hexlify(key))
        
        # check password (unofficial method), see http://blog.zorinaq.com/brute-forcing-rar-archives-encrypted-with-the-hp-option/
        if AES.new( bytes(key), AES.MODE_CBC, bytes(iv) ).decrypt(data[ -16: ])==unhexlify(b'c43d7b00400700000000000000000000'):
          print(self.depth*'  '+'encrypted headers: AES key is OK')
        self.currentOffset += Rar3.SALT_SIZE    
          
        # decrypt next header block (to get size) 
        encrypted = data[ self.currentOffset:self.currentOffset+AES_BLOCK_LEN ] 
        decryptedHeader = AES.new( bytes(key), AES.MODE_CBC, bytes(iv) ).decrypt( encrypted )
        headCrc, headType, headFlags, headSize = self.parseMarkerBlock( decryptedHeader )
        
        # decrypt for the full header given headSize
        l = headSize//AES_BLOCK_LEN * AES_BLOCK_LEN
        paddingLen = AES_BLOCK_LEN - (headSize%AES_BLOCK_LEN)
        if paddingLen > 0:
          l += AES_BLOCK_LEN
        encrypted = data[ self.currentOffset:self.currentOffset+l ] 
        decryptedHeader = AES.new( bytes(key), AES.MODE_CBC, bytes(iv) ).decrypt(encrypted)
        addSize = 0
        if headType!=Rar3.HEADER_TYPE_FILE and headFlags & Rar3.FILE_HEADER_HAS_ADD_SIZE:
           addSize = unpack('<L',decryptedHeader[ Rar3.S_BLOCK_HDR.size: Rar3.S_BLOCK_HDR.size+4 ])[0]

      print('Block header: crc %x' % headCrc, 'type %x (%s)' % (headType, Rar3.headerType[headType]), 'flags 0x%x' % headFlags, 'size %d ' % headSize, 'addsize',addSize)
        
      if headType == Rar3.HEADER_TYPE_ARCHIVE: #archive header
        headersEncrypted = (headFlags & Rar3.BLOCK_HEADER_ISENCRYPTED) > 0
        print((self.depth+1)*'  '+'headersEncrypted',headersEncrypted)        
      elif headType == Rar3.HEADER_TYPE_COMMENT: 
        pass
      elif headType == Rar3.HEADER_TYPE_FILE: 
        self.depth +=1
        if not headersEncrypted: #but with or without file encryption
          packSize, unpSize, filedata, method, fileCrc, salt = self.parseFileBlock( data[self.currentOffset+Rar3.S_BLOCK_HDR.size:], headSize, headFlags, addSize )

        else: #headerEncrypted
          packSize, unpSize, filedata, method, fileCrc, salt = self.parseFileBlock( decryptedHeader[Rar3.S_BLOCK_HDR.size:], headSize, headFlags, addSize )
          fileOffset = self.currentOffset +headSize +paddingLen
          filedata = data[fileOffset:fileOffset+packSize]

        if salt: #file encryption ?
          filedata = self.decryptFile( salt, filedata )[:unpSize]
          
        self.currentOffset += packSize
          
        if method==Rar3.METHOD_STORING and options.sha1sum: #store
          print(self.depth*'  '+'sha1 correct ?', sha1(filedata).hexdigest()==options.sha1sum)
        print(self.depth*'  '+"file crc OK ? ",fileCrc == crc32(filedata)) 
        self.depth -=1
      elif headType == Rar3.HEADER_TYPE_MARKER:
        pass
      elif headType == Rar3.HEADER_TYPE_TERMINATOR:  
        pass
      self.currentOffset += (headSize+addSize+paddingLen)  
    
class SevenZ:
  # http://cpansearch.perl.org/src/BJOERN/Compress-Deflate7-1.0/7zip/DOC/7zFormat.txt
  HEADER_MAGIC = b'7z\xbc\xaf\x27\x1c'
  S_ARC_HEADER = Struct('<BBLQQL') # Major(B), Minor(B), StartHeaderCRC(L), NextHeaderOffset(Q), NextHeaderSize (Q), NextHeaderCRC (L)
  CODECS_COPY = b'\x00'
  CODECS_7Z_AES = b'\x06\xf1\x07\x01' # see SDK, doc/methods.txt : 7zAES (AES-256 + SHA-256)
  codecsNames = { CODECS_COPY:'copy', CODECS_7Z_AES:'7zAES' }
  CODECS_ITERATIONS_MASK     = 0b00111111
  CODECS_FLAG_HAS_IV_LEN     = 0b01000000
  CODECS_FLAG_HAS_SALT_LEN   = 0b10000000
  
  CODECS_SIZE_MASK           = 0b00001111
  CODERS_FLAG_IS_COMPLEX     = 0b00010000
  CODERS_FLAG_HAS_ATRIBUTES  = 0b00100000  
  IV_DEFAULT_LEN = 8
  SALT_DEFAULT_LEN = 8
  PID_END               = 0
  PID_HEADER            = 1
  PID_MAIN_STREAMS_INFO = 4
  PID_FILES_INFO        = 5
  PID_PACK_INFO         = 6
  PID_UNPACK_INFO       = 7
  PID_SUBSTREAM_INFO    = 8
  PID_SIZE              = 9
  PID_CRC               = 0xa
  PID_FOLDER            = 0xb
  PID_CODER_UNPACK_SIZE = 0xc
  PID_NAMES             = 0x11
  PID_MTIME             = 0x14
  PID_ATTRIBUTES        = 0x15
  PID_ENCODED_HEADER    = 0x17
  PID_DUMMY             = 0x19
  propertyNames= { PID_END:'End', PID_HEADER:'Header', PID_MAIN_STREAMS_INFO:'MainStreamsInfo', PID_FILES_INFO:'FilesInfo',
  PID_PACK_INFO:'PackInfo', PID_UNPACK_INFO:'UnPackInfo', PID_SUBSTREAM_INFO:'SubStreamsInfo', PID_SIZE:'Size', PID_CRC:'Crc', 
  PID_FOLDER:'Folder', PID_CODER_UNPACK_SIZE:'CodersUnPackSize', PID_NAMES:'Names', PID_MTIME:'mTime', PID_ATTRIBUTES:'Attributes',
  PID_ENCODED_HEADER:'EncodedHeader', PID_DUMMY:'Dummy'  }
  
  def __init__(self, data):
    self.currentOffset = 0
    self.dataLen = len(data)
    self.data = data
    self.depth = 0 #for options.verbose
    self.packInfo = dict()
    self.unpackInfo = dict()
    self.codecsId = dict()
    self.crc = dict()
    self.embedded = None
    
  # access data relatively to self.currentOffset, which is updated  
  def getReal64( self ): #variable 8 bytes integer encoding, see 7zFormat.txt, more efficient than RAR5 Vint
    mask  = 0b10000000
    prefix = 0b00000000
    size = 1      
    data = self.data
    while data[ self.currentOffset ]&mask != prefix and size<9:
      size +=1
      mask = (mask>>1) | 0b10000000
      prefix = (prefix>>1) | 0b10000000
    
    if size==1:  # prefix = 0xxxxxxx
      v = data[self.currentOffset]&(mask^0xff)
    else: # prefixes = 10xxxxxx, #110xxxxx ...
      v = (data[ self.currentOffset ]&(mask^0xff))<<(8*(size-1)) | int.from_bytes( data[self.currentOffset+1:self.currentOffset+size], byteorder='little' )
    self.currentOffset +=size
    return v
      
  # access data relatively to self.currentOffset, which is updated
  def getProperty( self ):
    p = self.data[ self.currentOffset ]
    self.currentOffset +=1
    #print(type(self.data),type(ord(p)), type(SevenZ.PID_HEADER))
    if options.verbose:
      if p==SevenZ.PID_END:
        self.depth -=1
      print(self.depth*'  '+'property=0x%x (%s)' % (p, SevenZ.propertyNames[p]) )
    return p
    
  def parsePackInfo(self):    
    data = self.data
    self.depth +=1  
    packPos = self.getReal64() 
    numPackStreams = self.getReal64( )     
    if options.verbose:
      print(self.depth*'  '+'packPos',packPos)
      print(self.depth*'  '+'numPackStreams',numPackStreams)
    property = self.getProperty()
    while property != SevenZ.PID_END:
      if property == SevenZ.PID_SIZE:
        for n in range(numPackStreams):
          size = self.getReal64() 
          if options.verbose:
            print(self.depth*'  '+'size 0x%x/%d'%(size,size) )
          self.packSize = size
          self.packInfo[n] = (packPos,size)
      property = self.getProperty()
    #print(self.packInfo)
  
  def keyDerivation(self):
    # see https://sourceforge.net/p/sevenzip/discussion/45798/thread/7cb978dc/, by Igor Pavlov, nov 2014
    hash = sha256()
    pwUtf16le = password.encode('utf-16le')
    """ test vector: password=hello, salt=0
    hash.update(680065006c006c006f00 0000000000000000), 
    hash.update(680065006c006c006f00 0100000000000000)"""
    for n in range(self.rounds):
      hash.update( pwUtf16le + pack('<Q',self.salt) )
      self.salt += 1
    #key = unhexlify('9f9182616d15e57fc1337920303b38b2ea0a592b953e4c5049014f850995e3ff')
    return hash.digest()  
  
  def parseFolder( self ):
    data = self.data
    numCoders = self.getReal64( ) 
    if options.verbose:
      print(self.depth*'  '+'numCoders',numCoders)
    self.depth +=1
    self.numInStreams = 0     
    self.numCodersOutStreams = 0
    for n in range(numCoders):
      flags = data[self.currentOffset]
      self.currentOffset += 1
      codecIdSize = flags & SevenZ.CODECS_SIZE_MASK
      codecId = data[self.currentOffset:self.currentOffset+codecIdSize]
      self.codecsId[n] = codecId
      self.currentOffset += codecIdSize
      if options.verbose:
        #print(self.depth*'  '+'+flags %x'% flags)
        print(self.depth*'  ', hexlify(codecId), SevenZ.codecsNames[codecId] )
        #print(self.depth*'  '+'codecIdSize', codecIdSize)
      if flags & SevenZ.CODERS_FLAG_IS_COMPLEX: #Is Complex Coders
        print(self.depth*'  '+'Is Complex Coder')
      else:
        numStreams = 1    
      if flags & SevenZ.CODERS_FLAG_HAS_ATRIBUTES: #There Are Attributes
        propertiesSize = self.getReal64()
        properties = data[self.currentOffset:self.currentOffset+propertiesSize]
        if options.verbose:
          print(self.depth*'  '+'There Are Attributes')
          print(self.depth*'  '+'propertiesSize', propertiesSize,end=': ')
          print(hexlify(properties) )
        # see https://sourceforge.net/p/sevenzip/discussion/45798/thread/7cb978dc/, by Igor Pavlov, nov 2014
        # see https://raw.githubusercontent.com/philsmd/7z2hashcat/master/7z2hashcat.pl, in get_decoder_properties()
        # see CEncoder::WriteCoderProperties() in CPP/7zip/Crypto/7zAes.cpp
        if codecId==SevenZ.CODECS_7Z_AES:
          iterations = properties[0] & SevenZ.CODECS_ITERATIONS_MASK
          #default values
          ivLen = SevenZ.IV_DEFAULT_LEN
          iv = b'\x00'*ivLen
          self.salt = unpack('<Q', b'\x00'*SevenZ.SALT_DEFAULT_LEN)[0]
          if properties[0] & SevenZ.CODECS_FLAG_HAS_SALT_LEN: #never seen
            print('CODECS_FLAG_HAS_SALT_LEN')
          if properties[0] & SevenZ.CODECS_FLAG_HAS_IV_LEN:
            #print(self.depth*'  '+'IV len flag')
            ivLen = properties[1]+1
            iv = properties[-ivLen:]
          self.rounds = 1 << iterations
          self.key = self.keyDerivation()
          if options.verbose :
            print(self.depth*'  '+'iterations: 2^%d,'%iterations, 'ivLen',ivLen,', IV',hexlify(iv))
            print(self.depth*'  '+'key:', hexlify(self.key))
          self.iv = iv+(16-ivLen)*b'\x00'
        self.currentOffset += propertiesSize
 
      self.numInStreams += numStreams  
    self.numCodersOutStreams += numCoders  
    nBonds = numCoders-1  
    if options.verbose :
      print(self.depth*'  '+'nBonds=', nBonds)
    for n in range(nBonds):
      packIndex = self.getReal64()
      unpackIndex = self.getReal64()
      if options.verbose :
        print((self.depth+1)*'  '+'packIndex %d, unpackIndex %d'%( packIndex, unpackIndex))
    self.numPackStreams = self.numInStreams - nBonds
    #print('numCodersOutStreams',self.numCodersOutStreams,'self.numInStreams',self.numInStreams)
    self.depth -=1
    
  def parseCrc(self):
    data = self.data
    allAreDefined = data[ self.currentOffset ]
    self.currentOffset += 1
    if allAreDefined == 0:
      print(self.depth*'  '+'allAreDefined', allAreDefined) 
    crc = unpack('<L',data[ self.currentOffset:self.currentOffset+4 ])[0]
    self.currentOffset += 4
    if options.verbose:
      print(self.depth*'  '+'crc %08x'% crc)
    self.crc[0] = crc
    
  def parseUnpackInfo(self ):
    data = self.data
    self.depth +=1
    property = self.getProperty()
    numFolders = 0
    while property != SevenZ.PID_END:
      if property == SevenZ.PID_FOLDER:
        numFolders = self.getReal64() 
        if options.verbose:
          print(self.depth*'  '+'numFolders',numFolders)
        external = data[ self.currentOffset ]
        self.currentOffset += 1
        if not external:
          for n in range(numFolders):
            self.parseFolder(  )
        else:
          print('external')        
      if property == SevenZ.PID_CODER_UNPACK_SIZE:
        for n in range(numFolders):
          for s in range(self.numCodersOutStreams):
            unpackSize = self.getReal64()
            if options.verbose:
              print(self.depth*'  '+'unpackSize 0x%x/%d'%(unpackSize, unpackSize) )
            self.unpackInfo[s] = unpackSize
      elif property==SevenZ.PID_CRC:
        self.parseCrc()      
      property = self.getProperty()
    #print(self.unpackInfo)  
        
  def parseSubStreamsInfo(self):
    data = self.data
    self.depth +=1
    property = self.getProperty()
    while property != SevenZ.PID_END:
      if property == SevenZ.PID_CRC:
        self.parseCrc()
      property = self.getProperty()
    
  def parseAddStreams(self):
    data = self.data
    self.depth +=1
    property = self.getProperty()
    while property != SevenZ.PID_END:
      if property==SevenZ.PID_PACK_INFO:
        self.parsePackInfo()
      elif property==SevenZ.PID_UNPACK_INFO:
        self.parseUnpackInfo()
      elif property==SevenZ.PID_SUBSTREAM_INFO:
        self.parseSubStreamsInfo()    
      property = self.getProperty()
    
  def getPackedData(self, entry=0, base=len(HEADER_MAGIC) + S_ARC_HEADER.size):
    data = self.data
    packedPos = self.packInfo[entry][0] + base
    packedSize = self.packInfo[entry][1]
    unpackedSize = self.unpackInfo[0] #method is copy, so out stream#0 and #1 have the same size
    packedData = data[ packedPos: packedPos+packedSize ]    
    #print('packedData',hexlify(packedData))
    return packedData, unpackedSize
    
  def parseFilesInfo(self):
    data = self.data
    self.depth +=1
    numFiles = self.getReal64()
    property = self.getProperty()
    size = self.getReal64()
    if options.verbose:
      print(self.depth*'  '+'numFiles', numFiles)
      print(self.depth*'  '+'size',size)
    while property != SevenZ.PID_END:    
      if options.verbose:
        if property==SevenZ.PID_NAMES:
          print(self.depth*'  ','"', data[self.currentOffset:self.currentOffset+size-1].decode('utf-16be'),'"' )
        elif property==SevenZ.PID_MTIME:
          print(self.depth*'  ', hexlify(data[self.currentOffset:self.currentOffset+size]) )
        elif property==SevenZ.PID_ATTRIBUTES:
          print(self.depth*'  ', hexlify(data[self.currentOffset:self.currentOffset+size]) )
        elif property==SevenZ.PID_DUMMY:  
          pass
      self.currentOffset += size 
      property = self.getProperty()
      if property!=SevenZ.PID_END:
        size = self.getReal64()
        
  def parseHeader(self):      
    data = self.data
    self.currentOffset += len(SevenZ.HEADER_MAGIC)
    #parse header  
    maj, min, crc, self.nextHeaderOffset, self.nextHeaderSize, nextCrc = SevenZ.S_ARC_HEADER.unpack_from( data[self.currentOffset:] )

    # first checksum is computed starting after the stored checksum (+6) until the end of the header
    header = data[ self.currentOffset+1+1+4 : self.currentOffset+SevenZ.S_ARC_HEADER.size ]
    
    self.currentOffset += SevenZ.S_ARC_HEADER.size
    self.currentOffset += self.nextHeaderOffset
    if options.verbose:
      print('7zip header')
      print('  maj',maj,'min',min,'crc %x'%crc,'offset 0x%x'%self.nextHeaderOffset,'size 0x%x'%self.nextHeaderSize, 'nextCrc %x'%nextCrc)
      print('  next = 0x%x'%self.currentOffset)
      print('  header crc OK ?', crc32(header)==crc  )
      print('  next section crc OK ?', crc32(data[self.currentOffset:self.currentOffset+self.nextHeaderSize])==nextCrc )   
        
  # http://www.7-zip.org/recover.html    
  # see p7zip_16.02\CPP\7zip\Archive\7z\7zIn.cpp
  def parse(self): 
    data = self.data
    property = self.getProperty()
    archive2 = None
    if property==SevenZ.PID_ENCODED_HEADER:
      self.parseAddStreams()
      #print('%x %x' %(self.packedPos,self.packedSize))
      packedData, unpackedSize = self.getPackedData() 
      if self.codecsId[0]==SevenZ.CODECS_7Z_AES:
        print(hexlify(packedData))
        decrypted = AES.new( bytes(self.key), AES.MODE_CBC, bytes(self.iv) ).decrypt(packedData)[:unpackedSize]
        print(hexlify(decrypted))
        print(self.depth*'  '+'decrypted headers CRC OK ?', crc32(decrypted)==self.crc[0])
        headerLen = len(SevenZ.HEADER_MAGIC)+SevenZ.S_ARC_HEADER.size
        encryptedPos = self.packInfo[0][0]
        newData = data[headerLen:headerLen+encryptedPos] + decrypted #recreate encrypted content, followed by decrypted headers
        #print(hexlify(newData))
        archive2 = SevenZ( newData )
        archive2.currentOffset += encryptedPos
        archive2.parse() #parse without header
        self.embedded = archive2
      else:
        print('not supported')      
    else: #normal header
      while self.currentOffset < self.dataLen and property!=SevenZ.PID_END:
        if property==SevenZ.PID_HEADER:
          self.depth +=1
        elif property==SevenZ.PID_MAIN_STREAMS_INFO:
          self.parseAddStreams( )
        elif property==SevenZ.PID_FILES_INFO:
          self.parseFilesInfo()  
        property = self.getProperty()

#minimal RAR5 implementation: support for 'store' method, content encryption and headers encryption        
class Rar5:
  HEADER_MAGIC = b'Rar!\x1A\x07\x01\x00'
  SALT_LEN = 16
  IV_LEN = 16
  WINTIME_SIZE = 8
  UNIXTIME_SIZE = 4
  
  HEADER_TYPE_MAIN       = 1
  HEADER_TYPE_FILE       = 2
  HEADER_TYPE_ENCRYPTION = 4
  HEADER_TYPE_END        = 5
  headerTypeName = { HEADER_TYPE_MAIN:'Main', HEADER_TYPE_FILE:'File', HEADER_TYPE_ENCRYPTION:'Encryption', HEADER_TYPE_END:'End' }
  FILE_EXTRA_TYPE_ENCRYPTION = 1
  FILE_EXTRA_TYPE_TIME       = 3
  extraTypeName = { FILE_EXTRA_TYPE_ENCRYPTION:"Encryption", FILE_EXTRA_TYPE_TIME:"Time" }
  
  ARCHIVE_FLAG_VOLNUM    = 0x0002
  ARCHIVE_FLAG_VOLUME = 0x0001
  HEADER_FLAG_EXTRA      = 0x0001
  HEADER_FLAG_DATA       = 0x0002
  ARCHIVE_FLAG_SOLID      = 0x0004
  FILE_FLAG_MTIMEPRESENT = 0x0002
  FILE_FLAG_CRCPRESENT   = 0x0004    
  FILE_TIME_FLAG_UNIXFORMAT    = 0x0001
  FILE_TIME_FLAG_MTIME_PRESENT = 0x0002
  ENCRYPTION_FLAG_CHECKPRESENT  = 0x0001
  ENCRYPTION_FLAG_USETWEAKEDSUM = 0x0002  
  
  COMPRESS_METHOD_MASK = 0x0380
  COMPRESSION_METHOD_STORE = 0
  
  PASSWD_CHECK_SIZE = 8  
  PASSWD_SUM_CHECK_SIZE = 4  
  CHECK_VALUE_LEN = PASSWD_CHECK_SIZE+PASSWD_SUM_CHECK_SIZE
  SHA256_LEN = 32
  HEADER_CRC_LEN = 4
  
  def __init__(self, data):
    self.currentOffset = 0  
    self.data = data
    self.decryptedBuffer = None
    self.decryptedOffset = 0
    self.size = len(data)
    self.depth = 0
    
  #decode 'variable integer' from RAR5 format
  #update offset with number of bytes read
  #from  buffer
  def readVIntBuffer(self):  
    v = 0
    i = 0
    end = False
    while not end:
      v |= (self.decryptedBuffer[self.decryptedOffset+i] & 0b01111111 )<<(i*7)
      end = (self.decryptedBuffer[self.decryptedOffset+i] & 0b10000000)==0 #continuation bit set ?
      i += 1
    self.decryptedOffset += i  
    return v
    
  #from (buffered) file  
  def readVInt(self):
    self.decryptedBuffer = self.data[self.currentOffset:]
    self.decryptedOffset = 0
    v = self.readVIntBuffer()  
    self.currentOffset += self.decryptedOffset  
    return v

  def getVIntBufferSize(self): #not used
    v, i = self.readVIntBuffer()  
    return i
    
  def readLongLE(self):
    v = unpack('<L', self.data[self.currentOffset:self.currentOffset+4])[0]
    self.currentOffset += 4
    return v
    
  def readLongLEBuffer(self):
    v = unpack('<L', self.decryptedBuffer[self.decryptedOffset:self.decryptedOffset+4])[0]
    self.decryptedOffset += 4
    return v
    
  def readBytes(self, n):  
    v = self.data[self.currentOffset:self.currentOffset+n]
    self.currentOffset += n
    return v
    
  def readBytesBuffer(self, n):  
    v = self.decryptedBuffer[self.decryptedOffset:self.decryptedOffset+n]
    self.decryptedOffset += n
    return v
    
  def parseMainHeader(self, headerFlags):
    extraSize = 0
    if headerFlags & Rar5.HEADER_FLAG_EXTRA:
      extraSize = self.readVInt()
    if headerFlags & Rar5.ARCHIVE_FLAG_VOLUME:
      print(self.depth*'  '+'ARCHIVE_FLAG_VOLUME')
    archiveFlags = self.readVInt()
    volNum = -1
    if archiveFlags & Rar5.ARCHIVE_FLAG_VOLNUM:
      volNum = self.readVInt()  
    if headerFlags & Rar5.ARCHIVE_FLAG_SOLID:
      print(self.depth*'  '+'ARCHIVE_FLAG_SOLID')
    print(self.depth*'  '+'extraSize', extraSize, 'archiveFlags', archiveFlags, 'volNum', volNum) 
    extra = self.data[self.currentOffset:self.currentOffset+extraSize]
    print(self.depth*'  '+'extra:', hexlify(extra))
    if extraSize>0:
      #extraOffset = 0
      innerExtraSize = self.readVInt()
      extraTypeOffset = self.currentOffset
      extraType = self.readVInt()
      extraData = self.data[extraTypeOffset: extraTypeOffset+innerExtraSize]
      print('  innerExtraSize', innerExtraSize, 'extraType', extraType, 'extraData:', hexlify(extraData) ) 
      self.currentOffset = extraTypeOffset+innerExtraSize

  def passwordCheck(self, v2, checkValue):    
    pwcheck = bytearray(Rar5.PASSWD_CHECK_SIZE)
    for i in range(Rar5.SHA256_LEN):
      pwcheck[ i%Rar5.PASSWD_CHECK_SIZE ] ^= v2[i]
    #print(hexlify(pwcheck))  
    #computed xor value (called pwcheck, 8 bytes) must be equal to first 8 bytes of 12 bytes 'password check' from File encryption record
    #first 4 bytes of sha256(pwcheck) must be equal of 4 last bytes of 'password check' from File encryption record
    check1 = pwcheck==checkValue[:Rar5.PASSWD_CHECK_SIZE]
    #size_t Archive::ReadHeader50(), arcread.cpp
    check2 = sha256(pwcheck).digest()[:Rar5.PASSWD_SUM_CHECK_SIZE]==checkValue[Rar5.PASSWD_CHECK_SIZE:]
    print(self.depth*'  '+'passwd check OK ?',check1, ', hash value OK ?',check2 )
    return check1, check2
    
  def keyDerivation(self, password, salt, count):    
    # unrar, cryp5.cpp, line 123 :  pbkdf2((byte *)PwdUtf,strlen(PwdUtf),Salt,SIZE_SALT50,Key,HashKeyValue,PswCheckValue,(1<<Lg2Cnt));
    # unrar, cryp5.cpp, TestPBKDF2()
    if count > 18:
      print('kdf count > 18')
      exit()
    counter = 1  
    hashdata = salt + pack('>L',counter)  
    #print(hexlify(hashdata))
    myhmac = hmac.new( bytes(password,'utf-8'), hashdata, sha256).digest()
    print(self.depth*'  '+'hmac_sha256(password,hashdata)',hexlify(myhmac))
    aeskey = PBKDF2(password, salt, dkLen=32, count=1<<count, prf=lambda p,s:HMAC.new(p,s,SHA256).digest() )  
    # b'a9356e422f3d7fcd8a9b851697cda8d96e6741e46a5e443b490dfb8a4ddcee52'
    print(self.depth*'  '+'AES key',hexlify(aeskey))
    # for tweaked checksum
    # b'358eb01bed0cc6d9e6c4f8fef1b02adf173215e59325f70c788d46bc5b678464'
    v1 = PBKDF2(password, salt, dkLen=32, count=(1<<count)+16, prf=lambda p,s:HMAC.new(p,s,SHA256).digest() )  
    print(self.depth*'  '+'v1',hexlify(v1))
    #password check
    # b'447751b5b3a8d51651d60e7ed36beb70ed0dc8e985a1f6c869bb0917c138d9f2'
    v2 = PBKDF2(password, salt, dkLen=32, count=(1<<count)+32, prf=lambda p,s:HMAC.new(p,s,SHA256).digest() )  
    print(self.depth*'  '+'v2',hexlify(v2))
    return aeskey, v1, v2
      
  def decryptFile(self, filedata):   
    if password is None:
      print('please provide the password using -p option')
      sys.exit()  
    aeskey, v1, v2 = self.keyDerivation(password, self.salt, self.kdfCount)
    c1, c2 = self.passwordCheck( v2, self.checkValue )  
    #filedata = unhexlify(b'980e59a480bc042c0e568e82f0a539c66d7becb24a41065f2909b73cdec2ce10')
    decrypted = AES.new( bytes(aeskey), AES.MODE_CBC, bytes(self.iv) ).decrypt( filedata )
    #print(hexlify(decrypted),decrypted)  
    return decrypted
  
  # read encryption data from buffer
  def readEncryptionDataBuffer(self, readIv=False):
    version = self.readVIntBuffer()
    flags = self.readVIntBuffer()
    count = self.decryptedBuffer[self.decryptedOffset]
    self.decryptedOffset +=1
    salt = self.readBytesBuffer(Rar5.SALT_LEN)
    iv = b'\x00'*Rar5.IV_LEN
    if readIv:
      iv = self.readBytesBuffer(Rar5.IV_LEN)
    checkValue = b'\x00'*Rar5.CHECK_VALUE_LEN
    if flags & Rar5.ENCRYPTION_FLAG_CHECKPRESENT:
      checkValue = self.readBytesBuffer(Rar5.CHECK_VALUE_LEN)
    return version, flags, count, salt, iv, checkValue
    
  # read encryption data from file  
  def readEncryptionData(self, readIv):
    self.decryptedBuffer = self.data[self.currentOffset:]
    self.decryptedOffset = 0
    version, flags, count, salt, iv, checkValue =  self.readEncryptionDataBuffer(readIv)
    self.currentOffset += self.decryptedOffset
    return version, flags, count, salt, iv, checkValue

  # parse file block from buffer
  def parseFileHeaderBuffer(self, headerFlags):
    extraSize = 0
    if headerFlags & Rar5.HEADER_FLAG_EXTRA:
      extraSize = self.readVIntBuffer()
    dataSize = 0  
    if headerFlags & Rar5.HEADER_FLAG_DATA:
      dataSize = self.readVIntBuffer()  
    fileFlags = self.readVIntBuffer()     
    unpackedSize = self.readVIntBuffer()     
    attributes = self.readVIntBuffer()     
    if fileFlags & Rar5.FILE_FLAG_MTIMEPRESENT:
      mtime = self.readLongLEBuffer()
    if fileFlags & Rar5.FILE_FLAG_CRCPRESENT:
      dataCRC = self.readLongLEBuffer()
    comprInfo = self.readVIntBuffer()     
    hostOS = self.readVIntBuffer()     
    nameLen = self.readVIntBuffer()     
    filename = self.decryptedBuffer[self.decryptedOffset:self.decryptedOffset+nameLen]
    self.decryptedOffset += nameLen
    print(self.depth*'  '+'extraSize', extraSize, 'fileFlags %x'%fileFlags, 'dataSize', dataSize, 'unpackedSize', unpackedSize, 'dataCRC 0x%x' % dataCRC, 
      'comprInfo 0x%x'%comprInfo,  'hostOS', hostOS, 'filename', filename ) 
        
    while extraSize>0:
      innerExtraSize = self.readVIntBuffer()
      extraType = self.readVIntBuffer()
      extraData = self.decryptedBuffer[self.decryptedOffset:self.decryptedOffset+innerExtraSize-1] #we assume len(extratype==1) as vint
      print(self.depth*'  '+'innerExtraSize', innerExtraSize, 'extraType', extraType, '(%s)'%self.extraTypeName[extraType],'extraData:', hexlify(extraData) ) 
      if extraType==Rar5.FILE_EXTRA_TYPE_ENCRYPTION: 
        self.depth +=1
        self.encrVersion, self.encrFlags, self.kdfCount, self.salt, self.iv, self.checkValue = self.readEncryptionDataBuffer(True) #also read IV
        print(self.depth*'  '+'encrVersion',self.encrVersion,'encrFlags %x' % self.encrFlags, 'kdfCount',self.kdfCount,'salt',hexlify(self.salt),
          'iv',hexlify(self.iv),'checkValue',hexlify(self.checkValue) )
        if self.encrFlags & Rar5.ENCRYPTION_FLAG_USETWEAKEDSUM:
          print(self.depth*'  '+'use tweaked checksum')      
        self.depth -=1  
      elif extraType==Rar5.FILE_EXTRA_TYPE_TIME:
        self.depth +=1
        flags = self.readVIntBuffer()
        if flags & Rar5.FILE_TIME_FLAG_MTIME_PRESENT:
          if not (flags & Rar5.FILE_TIME_FLAG_UNIXFORMAT):
            #https://msdn.microsoft.com/en-us/library/windows/desktop/ms724284(v=vs.85).aspx
            winFileTime = self.decryptedBuffer[self.decryptedOffset:self.decryptedOffset+Rar5.WINTIME_SIZE]
            self.decryptedOffset += Rar5.WINTIME_SIZE
            print(self.depth*'  '+'winFileTime', hexlify(winFileTime) )
          else:
            unixTime = self.decryptedBuffer[self.decryptedOffset:self.decryptedOffset+Rar5.UNIXTIME_SIZE] # not tested !
            self.decryptedOffset += Rar5.UNIXTIME_SIZE            
        self.depth -=1
      else:
        print(self.depth*'  '+'unsupported extratype')
      extraSize -= (innerExtraSize+1) # innerExtraSize must be stored in 1 Vint !
    return dataSize, comprInfo, unpackedSize
    
  def parseFileHeader(self, headerFlags):
    self.decryptedBuffer = self.data[self.currentOffset:]  
    self.decryptedOffset = 0
    dataSize, comprInfo, unpackedSize = self.parseFileHeaderBuffer( headerFlags )
    self.currentOffset += self.decryptedOffset
    return dataSize, comprInfo, unpackedSize
  
  def parseEncryptionHeader(self):
    version, flags, count, salt, iv, checkValue = self.readEncryptionData(False) #do not read IV
    print('encrVersion',version,'encrFlags %x' % flags, 'kdfCount',count,'salt',hexlify(salt),
          'iv',hexlify(iv),'checkValue',hexlify(checkValue) )
    aeskey, v1, v2 = self.keyDerivation(password, salt, count)  
    self.passwordCheck(v2, checkValue)
    return aeskey
    
  def readBlockHeaderBuffer(self):  
    crc = self.readLongLEBuffer()
    headerSizeOffset = self.decryptedOffset
    headerSize = self.readVIntBuffer()
    headerTypeOffset = self.decryptedOffset
    headerType = self.readVIntBuffer()
    headerFlags = self.readVIntBuffer()
    return crc, headerSize, headerType, headerFlags, crc32( self.decryptedBuffer[headerSizeOffset:headerTypeOffset+headerSize]  )
    
  def readBlockHeader(self):  
    crc = self.readLongLE()
    headerSizeOffset = self.currentOffset
    headerSize = self.readVInt()
    headerTypeOffset = self.currentOffset
    headerType = self.readVInt()
    headerFlags = self.readVInt() 
    return crc, headerSize, headerType, headerFlags, crc32( self.data[headerSizeOffset:headerTypeOffset+headerSize]  ) 

  def readFileData(self, dataSize, comprInfo, unpackedSize):
    if dataSize>0:
      filedata = self.readBytes(dataSize)
      if 'salt' in self.__dict__.keys(): #having a salt means file content is encrypted
        decrypted = self.decryptFile(filedata)
      else:
        decrypted = filedata
      comprMethod = (comprInfo & Rar5.COMPRESS_METHOD_MASK)>>7
      if comprMethod==Rar5.COMPRESSION_METHOD_STORE: #store
        if options.sha1sum: 
          print(self.depth*'  '+'sha1 correct ?', sha1(decrypted[:unpackedSize]).hexdigest()==options.sha1sum)
      else:  
        print(self.depth*'  '+'compression method (0x%x) not supported'%comprMethod)

    
  def parse(self):
    self.currentOffset = len(Rar5.HEADER_MAGIC)
    endOfRar = False
    encryptedHeaders = False
    while not endOfRar:
      if not encryptedHeaders:
        crc, headerSize, headerType, headerFlags, computedCrc = self.readBlockHeader()
        print(self.depth*'  '+'Block header: crc %08x' % crc, 'headerSize', headerSize, 'headerType', headerType, '(%s)'%self.headerTypeName[headerType], 'headerFlags %x' % headerFlags)    
        dataSize = 0
        self.depth += 1
        if headerType == Rar5.HEADER_TYPE_MAIN:
          self.parseMainHeader( headerFlags )
        elif headerType == Rar5.HEADER_TYPE_FILE:
          self.depth += 1
          dataSize, comprInfo, unpackedSize = self.parseFileHeader( headerFlags ) #self.currentOffset has been updated using self.decryptedOffset
          self.readFileData( dataSize, comprInfo, unpackedSize )
          self.depth -= 1
        elif headerType == Rar5.HEADER_TYPE_END:  
          endOfRar = True
        elif headerType == Rar5.HEADER_TYPE_ENCRYPTION:
          self.headerKey = self.parseEncryptionHeader()
          encryptedHeaders = True
        self.depth -=1
      else:    
        print(self.depth*'  '+'EncryptedHeaders')

        self.depth +=1
        while not endOfRar and self.currentOffset < self.size:
          self.depth +=1
          iv = self.readBytes(Rar5.IV_LEN)
          print(self.depth*'  '+'iv=',hexlify(iv))
          #if headerFlags & Rar5.ARCHIVE_FLAG_SOLID:
          #first read and decrypt block header to get real size to decrypt
          encrypted = self.data[self.currentOffset:self.currentOffset+AES_BLOCK_LEN]
          print(self.depth*'  '+'encrypted=%s'%hexlify(encrypted))
          self.decryptedBuffer = AES.new( bytes(self.headerKey), AES.MODE_CBC, bytes(iv) ).decrypt( encrypted )
          self.decryptedOffset = 0
          print(self.depth*'  '+'decrypted=%s'%hexlify(self.decryptedBuffer))        
          crc, headerSize, headerType, headerFlags, computedCrc = self.readBlockHeaderBuffer()

          padLen = AES_BLOCK_LEN-(headerSize+Rar5.HEADER_CRC_LEN)%AES_BLOCK_LEN
          #real length to read and decrypt
          encryptedLen = 4+headerSize+padLen #4 is CRC_LEN
          #read entire block up to filedata
          encrypted = self.readBytes(encryptedLen)

          self.decryptedBuffer = AES.new( bytes(self.headerKey), AES.MODE_CBC, bytes(iv) ).decrypt( encrypted )
          self.decryptedOffset = 0
          crc, headerSize, headerType, headerFlags, computedCrc = self.readBlockHeaderBuffer()

          print(self.depth*'  '+'Block header: crc %08x' % crc, 'headerSize', headerSize, 'headerType', headerType, '(%s)'%self.headerTypeName[headerType], 'headerFlags %x' % headerFlags)    

          dataSize = 0
          if headerType == Rar5.HEADER_TYPE_FILE: #parse in buffer
            self.depth +=1
            dataSize, comprInfo, unpackedSize = self.parseFileHeaderBuffer( headerFlags ) #do not need to update self.currentOffset, as it has been done by self.readBytes(encryptedLen)
            self.readFileData( dataSize, comprInfo, unpackedSize )
            self.depth -=1
          elif headerType== Rar5.HEADER_TYPE_MAIN:  
            pass
          elif headerType== Rar5.HEADER_TYPE_END:  
            endOfRar = True
          else:
            print(self.depth*'  '+'unknown headerType',headerType)    
          self.depth -=1  
        print('Header CRC OK ?',  crc==computedCrc )
      self.depth -=1    
      
if data[:6]==SevenZ.HEADER_MAGIC: #7zip
  archive = SevenZ( data )
  archive.parseHeader()
  archive.parse()
  crc = archive.crc[0]
  if archive.embedded: #with headers encryption, a new archive is created with decrypted data, stored in 'embedded'
    packedData, unpackedSize = archive.embedded.getPackedData(0, 0) # entry #0, base = 0 (no header)
    iv = archive.embedded.iv
    key = archive.embedded.key
    crc = archive.embedded.crc[0]
  else:  
    if archive.codecsId[0]==SevenZ.CODECS_7Z_AES:
      iv = archive.iv
      key = archive.key
    # simple AES and 'copy' codecs      
    packedData, unpackedSize = archive.getPackedData()

  #only working with first entry
  if archive.codecsId[0]==SevenZ.CODECS_7Z_AES:
    decrypted = AES.new( bytes(key), AES.MODE_CBC, bytes(iv) ).decrypt(packedData)[:unpackedSize]
    unpacked = decrypted
  elif archive.codecsId[0]==SevenZ.CODECS_COPY:  
    unpacked = packedData
  else:
    print('unsupported codec %s', hexlify(archive.codecsId[0]) )
    exit()
  if options.sha1sum:       
    print('sha1 correct ?', sha1(unpacked).hexdigest()==options.sha1sum)
  print('crc32 correct ?', crc32(unpacked)==crc)        
  
elif data[:7]==Rar3.HEADER_MAGIC:  
  archive = Rar3( len(data) )
  archive.parse( data )

elif data[:8]==Rar5.HEADER_MAGIC: 
  archive = Rar5( data )
  archive.parse()
  
else:
  #maybe zip  
  endCentralDir =  data.rfind(Zip.EOCENTRAL_MAGIC)
  if endCentralDir!=-1:
    archive = Zip(data, endCentralDir )
    archive.parse()
  else:
    print('unknown format')
