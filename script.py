import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import struct
import sys
from datetime import datetime, timezone

if sys.platform != 'win32':
    sys.exit('Windows only: uses IOCTL_SCSI_PASS_THROUGH_DIRECT.')

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING = 1, 2, 3
IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014
SCSI_IOCTL_DATA_IN = 1
MAX_TRANSFER = 252

# bindings
k32 = C.WinDLL('kernel32', use_last_error=True)
k32.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p,
                             W.DWORD, W.DWORD, W.HANDLE]
k32.CreateFileW.restype = W.HANDLE
k32.DeviceIoControl.argtypes = [W.HANDLE, W.DWORD, C.c_void_p, W.DWORD,
                                 C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
k32.DeviceIoControl.restype = W.BOOL
k32.CloseHandle.argtypes = [W.HANDLE]
k32.CloseHandle.restype = W.BOOL
INVALID_HANDLE_VALUE = C.c_void_p(-1).value

class SPTD(C.Structure):
    _fields_ = [('Length', W.USHORT), ('ScsiStatus', C.c_ubyte),
                ('PathId', C.c_ubyte), ('TargetId', C.c_ubyte), ('Lun', C.c_ubyte),
                ('CdbLength', C.c_ubyte), ('SenseInfoLength', C.c_ubyte),
                ('DataIn', C.c_ubyte), ('DataTransferLength', W.ULONG),
                ('TimeOutValue', W.ULONG), ('DataBuffer', C.c_void_p),
                ('SenseInfoOffset', W.ULONG), ('Cdb', C.c_ubyte * 16)]

class Request(C.Structure):
    _fields_ = [('sptd', SPTD), ('sense', C.c_ubyte * 32)]

def log_sense(handle, page):
    data = (C.c_ubyte * MAX_TRANSFER)()
    req = Request()
    req.sptd.Length = C.sizeof(SPTD)
    req.sptd.CdbLength = 10
    req.sptd.SenseInfoLength = C.sizeof(req.sense)
    req.sptd.DataIn = SCSI_IOCTL_DATA_IN
    req.sptd.DataTransferLength = MAX_TRANSFER
    req.sptd.TimeOutValue = 10
    req.sptd.DataBuffer = C.addressof(data)
    req.sptd.SenseInfoOffset = Request.sense.offset
    req.sptd.Cdb[0] = 0x4D  # LOG SENSE(10)
    req.sptd.Cdb[2] = 0x40 | page  # PC=01 (cumulative), page code
    req.sptd.Cdb[7] = (MAX_TRANSFER >> 8) & 0xff
    req.sptd.Cdb[8] = MAX_TRANSFER & 0xff
    returned = W.DWORD()
    ok = k32.DeviceIoControl(handle, IOCTL_SCSI_PASS_THROUGH_DIRECT,
                             C.byref(req), C.sizeof(req), C.byref(req),
                             C.sizeof(req), C.byref(returned), None)
    if not ok:
        raise C.WinError(C.get_last_error())
    if req.sptd.ScsiStatus:
        raise RuntimeError(f'SCSI status 0x{req.sptd.ScsiStatus:02x}; '
                           f'sense={bytes(req.sense).hex(" ")}')
    raw = bytes(data)
    size = 4 + int.from_bytes(raw[2:4], 'big')
    if (raw[0] & 0x3f) != page or not 4 <= size <= MAX_TRANSFER:
        raise RuntimeError(f'Unexpected LOG SENSE header: {raw[:8].hex(" ")}')
    return raw[:size]


def u32(raw, offset):
    return struct.unpack_from('<I', raw, offset)[0] if len(raw) >= offset + 4 else None


FIELD_LABELS = {
    'controller_temp_c': 'Controller temperature (°C)',
    'nand_1_temp_c': 'NAND channel 1 temperature (°C)',
    'nand_2_temp_c': 'NAND channel 2 temperature (°C)',
    'nand_3_temp_c': 'NAND channel 3 temperature (°C)',
    'nand_4_temp_c': 'NAND channel 4 temperature (°C)',
    'highest_recorded_temp_c': 'Highest recorded temperature (°C)',
    'lowest_recorded_temp_c': 'Lowest recorded temperature (°C)',
    'board_a_temp_c': 'Board sensor A temperature (°C)',
    'board_b_temp_c': 'Board sensor B temperature (°C)',
    'host_reads_gib': 'Total host reads (GiB)',
    'host_writes_gib': 'Host writes (GiB)',
}


def display_name(key):
    return FIELD_LABELS.get(key, key.replace('_', ' ').capitalize())


def decode(page, raw):
    if page == 0x32:
        fields = [('controller_temp_c', 7), ('nand_1_temp_c', 8), ('nand_2_temp_c', 9),
                  ('nand_3_temp_c', 10), ('nand_4_temp_c', 11), ('highest_recorded_temp_c', 12),
                  ('lowest_recorded_temp_c', 13), ('board_a_temp_c', 16), ('board_b_temp_c', 21)]
        return {name: raw[offset] for name, offset in fields if offset < len(raw)}
    if page == 0x30:
        fields = [('host_writes_gib', 0x79), ('host_reads_gib', 0x81)]
        return {name: u32(raw, offset) for name, offset in fields if u32(raw, offset) is not None}
    return {}


def print_hexdump(raw):
    for offset in range(0, len(raw), 16):
        print(f'{offset:04x}: {raw[offset:offset+16].hex(" ")}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('disk', type=int, help='PhysicalDrive number (Get-Disk)')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--page', type=lambda s: int(s, 0), choices=[0x30, 0x31, 0x32], default=0x32)
    group.add_argument('--all', action='store_true', help='Read pages 0x30, 0x31, and 0x32')
    parser.add_argument('--save', metavar='FILE.json', help='Save raw hex and decoded fields for comparisons')
    parser.add_argument('--compare', metavar='FILE.json', help='Compare against a saved snapshot')
    parser.add_argument('--no-hex', action='store_true', help='Hide hex dump in terminal')
    args = parser.parse_args()
    path = rf'\\.\PhysicalDrive{args.disk}'
    handle = k32.CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                             OPEN_EXISTING, 0, None)
    if handle == INVALID_HANDLE_VALUE:
        raise C.WinError(C.get_last_error())
    snapshot = {'disk': args.disk, 'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'pages': {}}
    try:
        for page in ([0x30, 0x31, 0x32] if args.all else [args.page]):
            raw = log_sense(handle, page)
            fields = decode(page, raw)
            snapshot['pages'][f'0x{page:02x}'] = {'raw_hex': raw.hex(), 'fields': fields}
            print(f'\n{path} page 0x{page:02x}, {len(raw)} bytes')
            if not args.no_hex:
                print_hexdump(raw)
            if fields:
                print('Decoded fields:')
                for name, value in fields.items():
                    print(f'  {display_name(name)}: {value}')
        if args.compare:
            before = json.loads(Path(args.compare).read_text(encoding='utf-8'))
            if before.get('disk') != args.disk:
                raise ValueError('WARN: Snapshot disk number differs')
            print('\nCounter changes since baseline:')
            for page, entry in snapshot['pages'].items():
                old = before.get('pages', {}).get(page, {}).get('fields', {})
                for key, value in entry['fields'].items():
                    if key in old and isinstance(value, int) and isinstance(old[key], int) and value != old[key]:
                        print(f'  {page} {display_name(key)}: {old[key]} -> {value} ({value-old[key]:+d})')
        if args.save:
            Path(args.save).write_text(json.dumps(snapshot, indent=2) + '\n', encoding='utf-8')
            print(f'\nSaved snapshot to {args.save}')
    finally:
        k32.CloseHandle(handle)

if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError) as exc:
        sys.exit(f'Error: {exc}')
