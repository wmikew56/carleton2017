import os
import datetime
import string
import time
import ctypes
import struct
import binascii
import calendar
import hashlib

BAD_TEST_ID = -1
BAD_EXPIRATION_TIME = -1


def script_error(err='Unspecified Error'):

    print err
    raise ValueError(err)


def dump_file(path, contents):

    f_handle = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0o600)
    os.write(f_handle, contents)
    os.close(f_handle)


def append_file(path, contents):

    f_handle = os.open(path, os.O_APPEND | os.O_RDWR)
    os.write(f_handle, contents)
    os.close(f_handle)


def load_file(path):

    try:
        with open(path, 'r') as f:
            data = f.read()
            return data
    except:
        raise ValueError("Unable to open/read %s" % path)


def safe_unlink(path):

    try:
        os.unlink(path)
        return True
    except Exception, e:
        return False


def list_files_in_dir(path):

    return [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]


def list_dirs_in_dir(path):

    return [d for d in os.listdir(path) if os.path.isfile(os.path.join(path, d))]


def parse_time_to_24hr_format(curr_time):

    new_datetime = datetime.datetime.strptime(curr_time, '%Y-%m-%dT%H:%M:%SZ')

    return long(new_datetime - datetime.datetime(1970, 1, 1).total_seconds())


def is_valid_job_count(count):

    if count >= 0 or count <= 0xFFFFFFFF:
        return True

    return False


def is_valid_port(port_str):

    try:
        port = int(port_str)
    except:
        return False

    if port == 0 or port > 0xFFFF:
        return False

    return True


def is_valid_student_id(stu_id):

    job_crypto = get_lib_job_crypto()
    raw_sha256_digest_len = job_crypto.jc_SHA256DigestLen()

    if len(stu_id) != 2 * raw_sha256_digest_len:
        return False

    return all(c in string.hexdigits for c in stu_id)


def is_valid_hashed_student_id_list(hashed_stu_ids):

    job_crypto = get_lib_job_crypto()

    for id in hashed_stu_ids:
        if job_crypto.jc_SHA256DigestLen() != len(id):
            return False

    return True


def is_valid_expiration_date(exp_date):

    if exp_date > gmtime_sec():
        return True

    return False


def is_valid_test_id_int(test_id):

    if test_id < 0 or test_id > 0xFFFFFFFF:
        return False

    return True


def is_valid_test_id_str(test_id_str):

    test_id = 0

    try:
        test_id = int(test_id_str)
    except Exception:
        return False

    return is_valid_test_id_int(test_id)


def parse_test_id(test_id_str):

    if is_valid_test_id_str(test_id_str):
        return int(test_id_str)

    script_error('Invalid Test ID: %s' % test_id_str)


def read_random_bytes(byte_count):

    with open('/proc/uptime', 'r') as uptime_fd:
        uptime_str = uptime_fd.read()
        uptime = float(uptime_str.split(' ')[0])

        wait_time_after_boot = 180
        if uptime < wait_time_after_boot:
            time.sleep(wait_time_after_boot - uptime)

        with open('/dev/urandom', 'r') as urandom_fd:
            random_bytes = urandom_fd.read(byte_count)
            assert len(random_bytes) == byte_count
            return random_bytes


def read_random_uint32():

    random_bytes = read_random_bytes(4)

    return struct.unpack('I', random_bytes)[0]


def read_random_uint8():

    random_bytes = read_random_bytes(1)

    return struct.unpack('B', random_bytes)[0]


def print_hex_32(num):

    return '0x%08x' % num


def print_hex_16(num):

    return '0x%04x' % num


def print_bytes(bytes):

    return binascii.b2a_hex(bytes)


def get_bytes(hex_string):

    return binascii.a2b_hex(hex_string)


def gmtime_sec():

    return calendar.timegm(time.gmtime())


def sha256_bytes(bytes):

    hash_imp = hashlib.sha256()
    hash_imp.update(bytes)

    return hash_imp.digest()


def get_lib_job_crypto():

    this_path = os.path.abspath(__file__)
    this_dir = os.path.dirname(this_path)
    libjc_path = os.path.join(this_dir, 'libjc.so')
    libjc_impl = ctypes.CDLL(libjc_path)
    libjc_impl.jc_BP512PublicKeyLen.argtypes = []
    libjc_impl.jc_BP512SharedSecretKeyLen.argtypes = []
    libjc_impl.jc_GENBP512KeyPair.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong
    ]
    libjc_impl.jc_GENBP512SharedSecret.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong
    ]
    libjc_impl.jc_BP512SignatureSize.argtypes = []
    libjc_impl.jc_BP512Sign.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong
    ]
    libjc_impl.jc_BP512VerifySignature.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
    ]
    libjc_impl.jc_SHA256DigestLen.argtypes = []
    libjc_impl.jc_GCMAES256KeyLen.argtypes = []
    libjc_impl.jc_GCMAES256TagLen.argtypes = []
    libjc_impl.jc_GCMAES256IVLen.argtypes = []
    libjc_impl.jc_GCMAES256Encrypt.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_ulonglong
    ]
    libjc_impl.jc_GCMAES256Decrypt.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p
    ]
    libjc_impl.jc_GCMAES256BlockSize.argtypes = []
    libjc_impl.jc_GCMAES256Decrypt.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_ulonglong, ctypes.c_char_p,
        ctypes.c_ulonglong
    ]

    return libjc_impl


def get_c_source_from_bin(bin, symbol_name, obfuscated=False):

    define_name = 'PROF_GENERATED_%s_H' % symbol_name.upper()
    c = [
        '#ifndef %s\n' % define_name,
        '#define %s\n\n' % define_name,
        '// This file is automatically generated at build time. Please do not edit\n',
        '// The variable is purposely not declared static, which is fine as long\n',
        '// as this file is only included once in the target.\n\n'
    ]

    if obfuscated:
        c.append('#include "common/obf_string.h"\n\n')

    c.append('namespace dprof\n')
    c.append('{\n\n')

    symbol_name_len = '%s_len' % symbol_name

    if obfuscated:
        symbol_name_arr = '%s_arr' % symbol_name
    else:
        symbol_name_arr = symbol_name

    c.append('\tconstexpr size_t %s = %s;\n\n' % (symbol_name, str(len(bin))))
    c.append('\tconstexpr unsigned char %s[%s] = \n{\n ' % (symbol_name_arr, symbol_name_len))

    for i in range(0, len(bin)):
        c.append('0x%02X' % (ord(bin[i])))
        if i + 1 != len(bin):
            c.append(', ')

            if i != 0 and (i + 1) % 12 == 0:
                c.append('\n')

    c.append('\n};\n\n ')

    if obfuscated:
        c.append('constexpr auto %s = DPOBF_ARR(%s, %s);\n\n' % (symbol_name, symbol_name_arr,
                                                                 symbol_name_len))

    c.append('} // namespace dprof\n\n')
    c.append('#endif // %s\n' % define_name)

    return ''.join(c)


def get_c_source_for_uint32(num, symbol_name):

    define_name = 'PROF_GENERATED_%s_H' % symbol_name.upper()

    c = [
        '#ifndef %s\n' % define_name,
        '#define %s\n\n' % define_name,
        '// This file is automatically generated at build time. Please do not edit\n',
        'namespace dprof\n',
        '{\n\n',
        'const uint32_t %s = 0x%04X;\n\n' % (symbol_name, num),
        '} // namespace dprof\n\n',
        '#endif // %s\n' % define_name
    ]

    return ''.join(c)


if __name__ == '__main__':

    script_error('ERROR: Do not call this script directly. '
                 'These are utility functions only.')
