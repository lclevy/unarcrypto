# unarcrypto.py #

v1.0

Laurent Clévy (@lorenzo2472), https://github.com/lclevy/

License is GPLv3

## Introduction ##

**unarcrypto.py** is an educational tool to depict the use of cryptography for password verification, headers and content encryption by popular archivers: zip, 7zip, rar v3 and v5.



Tested with PyCryptodome 3.7.0 and Python 3.6.1. Requires Python 3.3 and PyCrypto like

 

See also this article in French (soon public): https://connect.ed-diamond.com/MISC/MISC-092/Usage-de-la-cryptographie-par-les-formats-d-archives-ZIP-RAR-et-7z



Supported archives format, encryption and compression algorithms:

- zip (password protected or not, store or deflate, AES128/192?/256)
	
    - Key derivation (here for AES256): PBKDF2, 1000 iterations, hmac-sha1. 
    - Inputs: salt (16 bytes) and password. 
    - Outputs: AES key (32 bytes), password verification value (32 bytes), authentication code (2bytes)

    - Password verification: hmac-sha1 (first 80bits)

	- Encryption: AES256 in CTR mode, initial value is 1, counter has 128bits, little endian

- rar 3.x (password protected or not, encrypted headers, store, AES256)
	​	
	- Key derivation: custom algorithm using 1<<18 rounds of sha1 and a counter. 
	- Inputs: salt (8 bytes) and user password (utf-16le). 
	- Outputs: AES IV and key.

	- No password verification

	- Encryption: AES256 in CBC mode

- rar 5.x (password protected, store, AES)

    - Key derivation: PBKDF2 using hmac-sha256, 16 bytes salt from File Encryption record, with dklen=32. 
    - Initial value = salt + counter (32 bits, big endian, initial value=1). 
    - First "1<<count" rounds to compute AES 256 key, additionnal 16 rounds for Hash Key value, additionnal 16 rounds for Password Check value. 
    - Password Check is xored with 8 null bytes, then compared with first 8 bytes of Check Value from File Encrytion record. 
    - First 4 bytes of Sha256(first 8 bytes of Check Value) is compared to last 4 bytes of Check Value.

	- Encryption: AES256 CBC. IV from File Encryption record. Padded with 0.

- 7zip (password protected or not, store, AES256, encrypted headers)

    - Key generation: 2^rounds iterations. Sha256 over concatenation of password (UTF-16) and 8 bytes counter (little endian). Default salt is 0.

    - Content encryption: AES 256 CBC. Default IV is 8 bytes, padded with 0 (right). Parameters are stored in Header/MainStreamsInfo/UnPackInfo/Folder/Coders Attributes

    - Header encryption: parameters are stored in 'Encoded header' property. Encryption is like content protection


## References ##

ZIP

- [AES Encryption Information: Encryption Specification AE-1 and AE-2](http://www.winzip.com/win/en/aes_info.html "AES Encryption Information: Encryption Specification AE-1 and AE-2"), Winzip.com, January 30, 2009
- [A Password Based File Encryption Utility](http://www.gladman.me.uk/cryptography_technology/fileencrypt/ "A Password Based File Encryption Utility"), Brian Gladman, November 2008

RAR3

- [Brute Forcing RAR Archives Encrypted with the "-⁠hp" Option](http://blog.zorinaq.com/brute-forcing-rar-archives-encrypted-with-the-hp-option/ "Brute Forcing RAR Archives Encrypted with the \"\-⁠hp\" Option"), Marc Bevand, June 2010
- [Description of the RAR initialization routine](http://anrieff.net/ucbench/technical_qna.html#sec3 "Description of the RAR initialization routine") UnRAR-crack benchmark, Anrieff
- [RAR version 4.11 - Technical information](http://www.forensicswiki.org/w/images/5/5b/RARFileStructure.txt "RAR version 4.11 - Technical information"), forensicswiki.org
- [RAR version 3.93 - Technical information](https://github.com/php/pecl-file_formats-rar/blob/master/technote.txt "RAR version 3.93 - Technical information")
- [rarfile 3.0](https://pypi.python.org/pypi/rarfile/ "rarfile"), by Marko Kreen, rar3 and rar5 support. Very clean code and python package

RAR5

- [RAR 5.0 archive format](http://www.rarlab.com/technote.htm "RAR 5.0 archive format"), rarlab.com
- [Changes in RAR 5.0 encryption algorithm](http://www.rarlab.com/rarnew.htm "Changes in RAR 5.0 encryption algorithm"), rarlab.com


7zip

- [7z Format description (4.59)](http://cpansearch.perl.org/src/BJOERN/Compress-Deflate7-1.0/7zip/DOC/7zFormat.txt "7z"), See [SDK](http://www.7-zip.org/sdk.html "SDK")
- [Encryption and CRC information in 7z]( https://sourceforge.net/p/sevenzip/discussion/45798/thread/7cb978dc/ "Encryption and CRC information in 7z"), Igor Pavlov, november 2014

## Usage ##

	>python unarcrypto.py -h
	Usage: unarcrypto.py [options]
	
	Options:
	  -h, --help            show this help message and exit
	  -p PASSWORD, --pw=PASSWORD
	                        password
	  -s SHA1SUM, --sha1sum=SHA1SUM
	                        sha1sum
	  -v VERBOSE, --verbose=VERBOSE
	                        verbose
	
	>more tests\hello.txt
	hello world,hello world
	
	>sha1sum tests\hello.txt
	\76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 *tests\\hello.txt


- Zip examples

  - deflate, no password

      ```
      python unarcrypto.py -p hello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 tests\hello_deflate.zip
        	password= hello
      	0x000037: central entry: b'PK\x01\x02' name b'hello.txt' compressed 16 uncompressed 23 compression 8 localHeader 0
      	0x000000: local entry: b'PK\x03\x04' name  b'hello.txt' size 23 compressed 16 method 8 extraLen 0 crc efe883ba
       	     CRC on decompressed data is OK ? True
      ```

  - deflate, aes 256

       ```
       python unarcrypto.py -p hello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 tests\hello256_deflate.zip
       	password= hello
       	0x00005e: central entry: b'PK\x01\x02' name b'hello.txt' compressed 44 uncompressed 23 compression 99 localHeader 0
       	0x000000: local entry: b'PK\x03\x04' name  b'hello.txt' size 23 compressed 44 method 99 extraLen 11 crc 0
       	 extra: 9901 vendor 2 vendorId AE strength 3 method 8
       	  salt b'95e6ddb92a005af77ab52e00a2d669d7' pv b'd41e' auth code b'77cff0261858eb2c86b1'
       	   passwd verif OK ? True,   authCode OK ? True
       	   aes key b'2e69d2abca00601d0f0fcac4e9586e6266c58dce7b066b93d1de353f6a0ec605'
       	sha1 decompressed OK ?  True
       	 CRC on decrypted, then decompressed data is OK ? False
       ```

  - deflate, aes 128

       ```
       python unarcrypto.py -p hellohello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 tests\hello128_deflate.zip
       	password= hellohello
       	0x000056: central entry: b'PK\x01\x02' name b'hello.txt' compressed 36 uncompressed 23 compression 99 localHeader 0
       	0x000000: local entry: b'PK\x03\x04' name  b'hello.txt' size 23 compressed 36 method 99 extraLen 11 crc efe883ba
       	 extra: 9901 vendor 1 vendorId AE strength 1 method 8
       	  salt b'675bd3e4a7bbc1e8' pv b'5925' auth code b'8eca0aa15d90a06c7351'
       	   passwd verif OK ? True,   authCode OK ? True
       	   aes key b'cb94214a1e0c0c2261bed331a971ba93'
       	sha1 decompressed OK ?  True
       	 CRC on decrypted, then decompressed data is OK ? True
       ```

- Rar3 examples

  - store, no password

        python unarcrypto.py -p hellohello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 -v 1 tests\hello_nopw_store.rar
        password= hellohello
        Block header: crc 6152 type 72 (marker) flags 0x1a21 size 7  addsize 0
        Block header: crc 90cf type 73 (archive) flags 0x0 size 13  addsize 0
          headersEncrypted False
        Block header: crc b902 type 74 (file) flags 0x9020 size 46  addsize 0
          has ext_time
          no salt
          sha1 correct ? True
          file crc OK ?  True
        Block header: crc 3dc4 type 7b (terminator) flags 0x4000 size 7  addsize 0

  - store method with password

     ```
     python unarcrypto.py -p hello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 tests\hello_pw_store.rar
     	password= hello
       		Block header: crc 6152 type 72 (marker) flags 0x1a21 size 7  addsize 0
       		Block header: crc 90cf type 73 (archive) flags 0x0 size 13  addsize 0
      		headersEncrypted False
       		Block header: crc 44dc type 74 (file) flags 0x9424 size 54  addsize 0
      		has password
      		has ext_time
      		file salt b'728be58c227f8db4'
      		sha1 correct ? True
      		file crc OK ?  True
       		Block header: crc 3dc4 type 7b (terminator) flags 0x4000 size 7  addsize 0
     ```

  - store, headers encryption

     ```
     python unarcrypto.py -p hello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 tests\hello_pw_store_headers.rar
     	password= hello
     	Block header: crc 6152 type 72 (marker) flags 0x1a21 size 7  addsize 0
     	Block header: crc 99ce type 73 (archive) flags 0x80 size 13  addsize 0
     	  headersEncrypted True
     	header salt b'379475b06e303955'
     	iv b'e3dfe7498ad0faf3325f9ee9283a396c' key b'a002f7af8fc3b153436abb226f298747'
     	encrypted headers: AES key is OK
     	Block header: crc 4cd type 74 (file) flags 0x9424 size 54  addsize 0
     	  has password
     	  has ext_time
     	  file salt b'379475b06e303955'
     	  sha1 correct ? True
     	  file crc OK ?  True
     	header salt b'379475b06e303955'
     	iv b'e3dfe7498ad0faf3325f9ee9283a396c' key b'a002f7af8fc3b153436abb226f298747'
     	encrypted headers: AES key is OK
     	Block header: crc 3dc4 type 7b (terminator) flags 0x4000 size 7  addsize 0
     ```

- Rar5 examples
  - store, no password

        python unarcrypto.py -p hellohello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 -v 1 tests\hello5_nopw_store.rar
        password= hellohello
        Block header: crc e5b59233 headerSize 10 headerType 1 (Main) headerFlags 5
          ARCHIVE_FLAG_VOLUME
          ARCHIVE_FLAG_SOLID
          extraSize 6 archiveFlags 0 volNum -1
          extra: b'050101808000'
          innerExtraSize 5 extraType 1 extraData: b'0101808000'
        Block header: crc 2737b710 headerSize 37 headerType 2 (File) headerFlags 3
          extraSize 11 fileFlags 4 dataSize 23 unpackedSize 23 dataCRC 0xefe883ba comprInfo 0x0 hostOS 0 filename b'hello.txt'
          innerExtraSize 10 extraType 3 (Time) extraData: b'02bf2b20ff1e13d201'
            winFileTime b'bf2b20ff1e13d201'
          sha1 correct ? True
        Block header: crc 5156771d headerSize 3 headerType 5 (End) headerFlags 4

  - store, password

       ```
       python unarcrypto.py -p hello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 tests\hello5_pw_store.rar
         		password= hello
         		Block header: crc e5b59233 headerSize 10 headerType 1 (Main) headerFlags 5
         		  ARCHIVE_FLAG_VOLUME
         		  ARCHIVE_FLAG_SOLID
         		  extraSize 6 archiveFlags 0 volNum -1
         		  extra: b'050101808000'
         		  innerExtraSize 5 extraType 1 extraData: b'0101808000'
         		Block header: crc d5c0a057 headerSize 86 headerType 2 (File) headerFlags 3
         		  extraSize 60 fileFlags 4 dataSize 32 unpackedSize 23 dataCRC 0x292f7419 comprInfo 0x0 hostOS 0 filename b'hello.txt'
         		  innerExtraSize 48 extraType 1 (Encryption) extraData: '00030f3e8ecf5188a0ceae32cc0fdfc9ab9980825952411445b8610ccbe6b3eb05b81591179e35245a115c37811683'
         		    encrVersion 0 encrFlags 3 kdfCount 15 salt b'3e8ecf5188a0ceae32cc0fdfc9ab9980' iv b'825952411445b8610ccbe6b3eb05b815' checkValue b'91179e35245a115c37811683'
         		    use tweaked checksum
         		  innerExtraSize 10 extraType 3 (Time) extraData: b'02bf2b20ff1e13d201'
         		    winFileTime b'bf2b20ff1e13d201'
         		  hmac_sha256(password,hashdata) b'de1bf4c31403ca43d8538b4a0fb34fa3c67feffd74b7e2fd507e82b88cc22b74'
         		  AES key b'a9356e422f3d7fcd8a9b851697cda8d96e6741e46a5e443b490dfb8a4ddcee52'
         		  v1 b'358eb01bed0cc6d9e6c4f8fef1b02adf173215e59325f70c788d46bc5b678464'
         		  v2 b'447751b5b3a8d51651d60e7ed36beb70ed0dc8e985a1f6c869bb0917c138d9f2'
         		  passwd check OK ? True , hash value OK ? True
         		  sha1 correct ? True
         		Block header: crc 5156771d headerSize 3 headerType 5 (End) headerFlags 4
       ```

  - store, headers encryption

     ```
     python unarcrypto.py -p hello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 tests\hello5_pw_store_headers.rar
     	password= hello
     	Block header: crc f173e576 headerSize 33 headerType 4 (Encryption) headerFlags 0
     	encrVersion 0 encrFlags 1 kdfCount 15 salt b'4607a33dd66a62ce11fcf92dacaf18a4' iv b'00000000000000000000000000000000' checkValue b'55409bb46375e9a413a092b3'
     	  hmac_sha256(password,hashdata) b'39fda6189123b4aaad1480fc22c25dd0133f904677a80708c7485cc3d2d979fd'
     	  AES key b'955142f8b883fed673d632333a2c2c1d1a9712fa9a0e4bca2cfe47e4019ce6db'
     	  v1 b'7f6fb8f1562eb7838c319412fb3123c4477e0ff45632f3d2492487a5c22974b7'
     	  v2 b'52c7626f5eadd90d3c32bb2d7e72decb2d52a029cbd8fb2016e7e2df88721542'
     	  passwd check OK ? True , hash value OK ? True
     	EncryptedHeaders
     	  iv= b'aeebb6f529dd7e91d39df9512c569eba'
     	  Block header: crc e5b59233 headerSize 10 headerType 1 (Main) headerFlags 5
     	  iv= b'593ddbe07c9a5bd3537b157c0a38a855'
     	  Block header: crc 1cc698ab headerSize 86 headerType 2 (File) headerFlags 3
     	    extraSize 60 fileFlags 4 dataSize 32 unpackedSize 23 dataCRC 0xefe883ba comprInfo 0x0 hostOS 0 filename b'hello.txt'
     	    innerExtraSize 48 extraType 1 (Encryption) extraData: b'00010f4607a33dd66a62ce11fcf92dacaf18a4818141032c342fb3a3ddbc39336cf05e55409bb46375e9a413a092b3'
     	      encrVersion 0 encrFlags 1 kdfCount 15 salt b'4607a33dd66a62ce11fcf92dacaf18a4' iv b'818141032c342fb3a3ddbc39336cf05e' checkValue b'55409bb46375e9a413a092b3'
     	    innerExtraSize 10 extraType 3 (Time) extraData: b'02bf2b20ff1e13d201'
     	      winFileTime b'bf2b20ff1e13d201'
     	    hmac_sha256(password,hashdata) b'39fda6189123b4aaad1480fc22c25dd0133f904677a80708c7485cc3d2d979fd'
     	    AES key b'955142f8b883fed673d632333a2c2c1d1a9712fa9a0e4bca2cfe47e4019ce6db'
     	    v1 b'7f6fb8f1562eb7838c319412fb3123c4477e0ff45632f3d2492487a5c22974b7'
     	    v2 b'52c7626f5eadd90d3c32bb2d7e72decb2d52a029cbd8fb2016e7e2df88721542'
     	    passwd check OK ? True , hash value OK ? True
     	    sha1 correct ? True
     	  iv= b'b95da7f72ec46fc66196cc5de676d6b5'
     	  Block header: crc 5156771d headerSize 3 headerType 5 (End) headerFlags 4
     	Header CRC OK ? True 
     ```

- 7zip examples

  - store, no password

     ```
     py -3.3 unarcrypto.py tests\hello_nopw_store.7z -p hello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 -v 1
     ```

  - store, password

     ```
     python unarcrypto.py -p hello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 -v 1 tests\hello_pw_store.7z
     	password= hello
     	7zip header
     	  maj 0 min 4 crc aaf19fbc offset 0x20 size 0x6a nextCrc cfcf257a
     	  next = 0x40
     	  header crc OK ? True
     	  next section crc OK ? True
     	property=0x1 (Header)
     	  property=0x4 (MainStreamsInfo)
     	    property=0x6 (PackInfo)
     	      packPos 0
     	      numPackStreams 1
     	      property=0x9 (Size)
     	      size 0x20/32
     	    property=0x0 (End)
     	    property=0x7 (UnPackInfo)
     	      property=0xb (Folder)
     	      numFolders 1
     	      numCoders 2
     	         b'06f10701' 7zAES
     	        There Are Attributes
     	        propertiesSize 10: b'53073d86deae0075b499'
     	        iterations: 2^19, ivLen 8 , IV b'3d86deae0075b499'
     	        key: b'9f9182616d15e57fc1337920303b38b2ea0a592b953e4c5049014f850995e3ff'
     	         b'00' copy
     	        nBonds= 1
     	          packIndex 1, unpackIndex 0
     	      property=0xc (CodersUnPackSize)
     	      unpackSize 0x17/23
     	      unpackSize 0x17/23
     	    property=0x0 (End)
     	    property=0x8 (SubStreamsInfo)
     	      property=0xa (Crc)
     	      crc efe883ba
     	    property=0x0 (End)
     	  property=0x0 (End)
     	  property=0x5 (FilesInfo)
     	    property=0x19 (Dummy)
     	    numFiles 1
     	    size 11
     	    property=0x11 (Names)
     	     " hello.txt  "
     	    property=0x14 (mTime)
     	     b'0100bf2b20ff1e13d201'
     	    property=0x15 (Attributes)
     	     b'010020000000'
     	  property=0x0 (End)
     	property=0x0 (End)
     	sha1 correct ? True
     	crc32 correct ? True
     ```

  - store, headers encryption

     ```
     python unarcrypto.py -p hello -s 76d7a5a8d72da80c19acbd0f20f90dabac0c52f6 -v 1 tests\hello_pw_store_headers.7z
     	password= hello
     	7zip header
     	  maj 0 min 4 crc ae3af28b offset 0x90 size 0x26 nextCrc aff1c5eb
     	  next = 0xb0
     	  header crc OK ? True
     	  next section crc OK ? True
     	property=0x17 (EncodedHeader)
     	  property=0x6 (PackInfo)
     	    packPos 32
     	    numPackStreams 1
     	    property=0x9 (Size)
     	    size 0x70/112
     	  property=0x0 (End)
     	  property=0x7 (UnPackInfo)
     	    property=0xb (Folder)
     	    numFolders 1
     	    numCoders 1
     	       b'06f10701' 7zAES
     	      There Are Attributes
     	      propertiesSize 10: b'5307682473f9408c4d7c'
     	      iterations: 2^19, ivLen 8 , IV b'682473f9408c4d7c'
     	      key: b'9f9182616d15e57fc1337920303b38b2ea0a592b953e4c5049014f850995e3ff'
     	      nBonds= 0
     	    property=0xc (CodersUnPackSize)
     	    unpackSize 0x6a/106
     	    property=0xa (Crc)
     	    crc 08db1a35
     	  property=0x0 (End)
     	property=0x0 (End)
     	decrypted headers CRC OK ? True
     	property=0x1 (Header)
     	  property=0x4 (MainStreamsInfo)
     	    property=0x6 (PackInfo)
     	      packPos 0
     	      numPackStreams 1
     	      property=0x9 (Size)
     	      size 0x20/32
     	    property=0x0 (End)
     	    property=0x7 (UnPackInfo)
     	      property=0xb (Folder)
     	      numFolders 1
     	      numCoders 2
     	         b'06f10701' 7zAES
     	        There Are Attributes
     	        propertiesSize 10: b'530722a6129a1c599906'
     	        iterations: 2^19, ivLen 8 , IV '22a6129a1c599906'
     	        key: '9f9182616d15e57fc1337920303b38b2ea0a592b953e4c5049014f850995e3ff'
     	         b'00' copy
     	        nBonds= 1
     	          packIndex 1, unpackIndex 0
     	      property=0xc (CodersUnPackSize)
     	      unpackSize 0x17/23
     	      unpackSize 0x17/23
     	    property=0x0 (End)
     	    property=0x8 (SubStreamsInfo)
     	      property=0xa (Crc)
     	      crc efe883ba
     	    property=0x0 (End)
     	  property=0x0 (End)
     	  property=0x5 (FilesInfo)
     	    property=0x19 (Dummy)
     	    numFiles 1
     	    size 11
     	    property=0x11 (Names)
     	     " hello.txt  "
     	    property=0x14 (mTime)
     	     b'0100bf2b20ff1e13d201'
     	    property=0x15 (Attributes)
     	     b'010020000000'
     	  property=0x0 (End)
     	property=0x0 (End)
     	sha1 correct ? True
     	crc32 correct ? True
     ```


## Contributions ##

- Jean Baptiste Bedrune (@33c0) converted zip code using Construct declarative parser ([https://pypi.python.org/pypi/construct](https://pypi.python.org/pypi/construct "https://pypi.python.org/pypi/construct")), see ziparchive.py

## Related ##

- [7z2hashcat](https://github.com/philsmd/7z2hashcat "7z2hashcat"), extract information from .7z archives (and .sfx files) such that you can crack these "hashes" with hashcat 
- [zip2john.c](https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/src/zip2john.c "https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/src/zip2john.c"), extract info to crack using zip hash John the Ripper
- [rar2john.c](https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/src/rar2john.c "https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/src/rar2john.c"), extract rar3 info for cracking. 
- [rar5_fmt_plug.c](https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/src/rar5_fmt_plug.c "https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/src/rar5_fmt_plug.c"), rar5 plug-in for JtR
- [HashCat](https://hashcat.net/wiki/doku.php?id=example_hashes "HashCat") modes: 7zip is 11600, rar3-hp (header protection) is 12500, rar5 is 13000, zip is 13600 

## To do ##

- convert Rar and 7zip code to use Construct declarative parser 
- extract first file contents
