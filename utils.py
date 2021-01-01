import base64
import hashlib

ARR_RELATIVE_OFFSETS = list('14159265358979323846264338327950288419716939937510')


def calc_offsets(chash_len):
    arr_offsets = []
    offset = 0
    index = 0
    i = 0

    while offset < chash_len:
        relative_offset = int(ARR_RELATIVE_OFFSETS[i], 10)
        if relative_offset != 0:
            offset += relative_offset
            if chash_len == 288:
                offset += 4

            if offset >= chash_len:
                break

            arr_offsets.append(offset)
            index += 1

        i += 1

    if index != 32:
        raise Exception("wrong number of checksum bits")

    return arr_offsets


arrOffsets160 = calc_offsets(160)
arrOffsets288 = calc_offsets(288)


def get_source_string(obj):
    arr_components = []

    def extract_component(variable, arr_c=None):
        if variable is None:
            raise Exception("null value in {}".format(obj))
        if type(variable) == str:
            arr_c += ['s', variable]
            return
        elif type(variable) == int or type(variable) == float:
            arr_c += ['n', str(variable)]
            return
        elif type(variable) == bool:
            arr_c += ['b', str(variable)]
            return
        elif type(variable) == list:
            if len(variable) == 0:
                raise Exception("empty object in {}".format(obj))

            arr_c.append('[')
            for x in variable:
                extract_component(x, arr_c)
            arr_c.append(']')
            return
        elif type(variable) == dict:
            keys = sorted(variable.keys())
            for key in keys:
                try:
                    c = variable[key]
                    arr_c.append(key)
                    extract_component(c, arr_c)
                except KeyError:
                    raise Exception("undefined at {} of {}".format(key, obj))
            return
        else:
            raise Exception("hash: unknown type={} of {}, object: {}".format(type(variable), variable, obj))

    extract_component(obj, arr_components)
    return b'\x00'.decode('utf-8').join(arr_components)


def get_chash(data, chash_len):
    if chash_len == 160:
        h = hashlib.new("ripemd160")
        h.update(bytes(data, 'utf-8'))
    else:
        h = hashlib.new("sha256")
        h.update(bytes(data, 'utf-8'))

    h = h.digest()
    truncated_hash = h[4:] if chash_len == 160 else h
    checksum = get_checksum(truncated_hash)

    bin_clean_data = buffer2bin(truncated_hash)
    bin_checksum = buffer2bin(checksum)
    bin_chash = mix_checksum_into_clean_data(bin_clean_data, bin_checksum)
    chash = bin2buf(bin_chash)

    return (base64.b32encode(chash) if chash_len == 160 else base64.b64encode(chash)).decode('utf-8')


def get_checksum(clean_data):
    fc = hashlib.new('sha256')
    fc.update(clean_data)
    full_checksum = fc.digest()
    return bytes([full_checksum[5], full_checksum[13], full_checksum[21], full_checksum[29]])


def buffer2bin(buf):
    _bytes = []
    for x in buf:
        n = str(bin(x)[2:])
        if len(n) < 8:
            n = '00000000'[len(n):8] + n
        _bytes.append(n)

    return ''.join(_bytes)


def bin2buf(_bin):
    _len = int(len(_bin) / 8)
    buf = []
    for i in range(_len):
        offset = i * 8
        buf.append(int(_bin[offset: offset + 8], 2))
    return bytes(buf)


def mix_checksum_into_clean_data(bin_clean_data, bin_checksum):
    if len(bin_checksum) != 32:
        raise Exception("bad checksum length")

    _len = len(bin_clean_data) + len(bin_checksum)
    if _len == 160:
        arr_offsets = arrOffsets160
    elif _len == 288:
        arr_offsets = arrOffsets288
    else:
        raise Exception(f"bad length={_len}, clean data = {bin_clean_data}, checksum = {bin_checksum}")

    arr_frags = []
    arr_checksum_bits = list(bin_checksum)
    start = 0

    for i in range(len(arr_offsets)):
        end = arr_offsets[i] - i
        arr_frags.append(bin_clean_data[start:end])
        arr_frags.append(arr_checksum_bits[i])
        start = end

    if start < len(bin_clean_data):
        arr_frags.append(bin_clean_data[start:])

    return ''.join(arr_frags)


def get_chash_160(definition):
    return get_chash(get_source_string(definition), 160)
