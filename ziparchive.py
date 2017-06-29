import binascii
import os
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2

from construct import Struct, Int8ul, Int16ul, Int32ul, Const, String, Bytes, Enum, this


central_directory_file_header = Struct(
    signature=Const(b"\x50\x4b\x01\x02"),
    version_made_by=Int8ul[2],
    version_needed_to_extract=Int8ul[2],
    general_purpose_bit_flag=Int16ul,
    compression_method=Int16ul,
    last_mod_dos_datetime=Int32ul,  # last mod file time and last mod file date
    crc32=Int32ul,
    csize=Int32ul,  # compressed size
    ucsize=Int32ul,  # uncompressed size
    filename_length=Int16ul,
    extra_field_length=Int16ul,
    file_comment_length=Int16ul,
    dist_number_start=Int16ul,
    internal_file_attributes=Int16ul,
    external_file_attributes=Int32ul,
    relative_offset_local_header=Int32ul,
    filename=String(this.filename_length, "utf-8"),
    extra_field=Bytes(this.extra_field_length),
    file_comment=Bytes(this.file_comment_length)
)

local_file_header = Struct(
    signature=Const(b"\x50\x4b\x03\x04"),
    version_needed_to_extract=Int8ul[2],
    general_purpose_bit_flag=Int16ul,
    compression_method=Int16ul,
    last_mod_dos_datetime=Int32ul,  # last mod file time and last mod file date
    crc32=Int32ul,
    csize=Int32ul,  # compressed size
    ucsize=Int32ul,  # uncompressed size
    filename_length=Int16ul,
    extra_field_length=Int16ul,
    filename=String(this.filename_length, "utf-8"),
    extra_field=Bytes(this.extra_field_length)
)

end_central_dir_record = Struct(
    signature=Const(b"\x50\x4b\x05\x06"),
    number_this_disk=Int16ul,
    num_entries_centrl_dir_ths_disk=Int16ul,
    number_disk_start_cdir=Int16ul,
    total_entries_central_dir=Int16ul,
    size_central_directory=Int32ul,
    offset_start_central_directory=Int32ul,
    zipfile_comment_length=Int16ul,
    zipfile_comment=Bytes(this.zipfile_comment_length)
)

# http://www.winzip.com/win/en/aes_info.htm#zip-format
extra_header = Struct(
    header_id=Int16ul,
    data_size=Int16ul,
    version_number=Int16ul,
    vendor_id=Int8ul[2],
    encryption_strength=Enum(Int8ul, AES_128=1, AES_192=2, AES_256=3),
    compression_method=Int16ul
)

AUTH_CODE_LEN = 10
PASSWD_VERIF_LEN = 2
PBKDF2_ITER = 1000
NUM_COUNTER_BITS = 128


# for Zip with AES
class ZipArchive(object):
    EOCENTRAL_MAGIC = b'PK\x05\x06'
    AES_ENCRYPTED = 99

    def __init__(self, fd, password=None, sha1sum=None):
        fd.seek(-0x1000, os.SEEK_END)
        footer = fd.read()
        end_central_dir_offset = footer.rfind(ZipArchive.EOCENTRAL_MAGIC)
        if end_central_dir_offset == -1:
            raise ValueError("File is not a Zip archive")

        self.end_central_dir_offset = fd.tell() - len(footer) + end_central_dir_offset
        self.stream = fd
        self.password = password
        self.sha1sum = sha1sum

    @staticmethod
    def probe(fd):
        fd.seek(-0x1000, os.SEEK_END)
        footer = fd.read()
        if footer.rfind(ZipArchive.EOCENTRAL_MAGIC) != -1:
            return True
        return False

    def parse(self):
        # retrieve central directory offset
        self.stream.seek(self.end_central_dir_offset)
        end_central_dir = end_central_dir_record.parse_stream(self.stream)
        central_dir_offset = end_central_dir.offset_start_central_directory

        # iterate on every local file header
        while central_dir_offset < self.end_central_dir_offset:
            self.stream.seek(central_dir_offset)
            cdfh = central_directory_file_header.parse_stream(self.stream)

            local_header_offset = cdfh.relative_offset_local_header
            central_dir_offset = self.stream.tell()

            self.stream.seek(local_header_offset)
            lfh = local_file_header.parse_stream(self.stream)

            if lfh.extra_field_length != 0:
                aes_extra_data = extra_header.parse(lfh.extra_field)
                encryption_strength = aes_extra_data.encryption_strength
            else:
                encryption_strength = 0
            compression = lfh.compression_method
            compressed = lfh.csize

            if compression == ZipArchive.AES_ENCRYPTED:
                compressed_data = self.decrypt_file(compressed, encryption_strength)
                file_content = zlib.decompress(compressed_data, -15)
            else:
                file_content = zlib.decompress(self.stream.read(compressed), -15)

            if self.sha1sum:
                print('sha1 decompressed OK? ', SHA.new(file_content).hexdigest() == self.sha1sum)

            if cdfh.crc32 != 0:
                print(' CRC on decompressed data is OK?', cdfh.crc32 == zlib.crc32(file_content))

    def decrypt_file(self, compressed_size, encryption_strength):
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
        # compressed length includes salt, password verification value and authentication code...
        encryption_params = {  # [ salt len, key len ], WinZip v21 can create aes128 (1) and 256 (3) ...
            "AES_128": [8, 16],
            "AES_192": [12, 24],
            "AES_256": [16, 32]
        }
        if encryption_strength not in encryption_params:
            raise NotImplementedError("Unsupported encryptionStrength")

        salt_len, key_len = encryption_params[encryption_strength]
        salt = self.stream.read(salt_len)
        password_verification_value = self.stream.read(PASSWD_VERIF_LEN)

        compressed_file_size = compressed_size - (salt_len + PASSWD_VERIF_LEN + AUTH_CODE_LEN)
        encrypted_data = self.stream.read(compressed_file_size)
        authentication_code = self.stream.read(AUTH_CODE_LEN)

        print('  salt', binascii.hexlify(salt),
              'pv', binascii.hexlify(password_verification_value),
              'auth code', binascii.hexlify(authentication_code))

        # If prf is not specified, PBKDF2 uses HMAC-SHA1
        keys = PBKDF2(self.password, salt, dkLen=key_len * 2 + PASSWD_VERIF_LEN, count=PBKDF2_ITER)

        print('   passwd verif OK?', keys[-2:] == password_verification_value, end=',')

        aes_key, hmac_key = keys[:key_len], keys[key_len:key_len + key_len]
        myhmac = HMAC.new(hmac_key, encrypted_data, SHA).digest()
        print('   authCode OK?', myhmac[:10] == authentication_code)

        ctr = Counter.new(nbits=NUM_COUNTER_BITS, initial_value=1, little_endian=True)
        compressed_data = AES.new(aes_key, AES.MODE_CTR, counter=ctr).decrypt(encrypted_data)
        print('   aes key', binascii.hexlify(keys[:key_len]))
        print(binascii.hexlify(compressed_data))
        return compressed_data


if __name__ == "__main__":
    with open("tests/42.zip", "rb") as zip_file:
        if ZipArchive.probe(zip_file):
            archive = ZipArchive(zip_file, "42")
            archive.parse()
