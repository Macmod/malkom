from elftools.elf.sections import SymbolTableSection
from elftools.elf.elffile import ELFFile
from pefile import PE
import hashlib
import magic
import re
import os


def get_overlay_offset(fname):
    ftype = filetype(fname)

    offset = None
    if ftype == 'PE':
        offset = pe_get_overlay_offset(fname)
    elif ftype == 'ELF':
        offset = elf_get_overlay_offset(fname)

    return offset


def elf_get_overlay_offset(fname):
    offset = -1
    fsize = os.stat(fname).st_size
    try:
        with open(fname, 'rb') as myfile:
            elf = ELFFile(myfile)

            start_last_section = elf.header['e_shoff']
            size_section_header = elf.header['e_shentsize']
            n_section_headers = elf.header['e_shnum']

            offset = start_last_section + size_section_header * n_section_headers
            if offset == fsize:
                offset = None
    except Exception:
        pass

    return offset


def pe_get_overlay_offset(fname):
    offset = -1
    try:
        pe = PE(fname)
        offset = pe.get_overlay_data_start_offset()
    except Exception:
        pass

    return offset


def jaccard(l1, l2):
    s1 = set(l1)
    s2 = set(l2)
    inters = s1.intersection(s2)
    union = s1.union(s2)

    interslen = len(inters)
    unionlen = len(union)
    if unionlen == 0:
        return None

    metric = float(interslen) / unionlen
    return metric


def filetype(filename):
    magictype = magic.from_file(filename)
    if re.match(r'^PE[0-9]{2}|^MS-DOS', magictype):
        return 'PE'
    elif magictype.startswith('ELF'):
        return 'ELF'
    else:
        return 'UNKNOWN'


def filehash(filename):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def contenthash(contents):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(contents)
    return sha256_hash.hexdigest()


def pe_get_imports(mype):
    if not hasattr(mype, 'DIRECTORY_ENTRY_IMPORT'):
        return []

    return list(
        map(
            lambda x: (
                x.dll.decode('utf-8'),
                list(
                    map(
                        lambda x: x.name.decode('utf-8') if x.name is not None else '',
                        x.imports
                    )
                )
            ), mype.DIRECTORY_ENTRY_IMPORT
        )
    )


def pe_get_exports(mype):
    if not hasattr(mype, 'DIRECTORY_ENTRY_EXPORT'):
        return []

    symbols = mype.DIRECTORY_ENTRY_EXPORT.symbols
    exports = [
        exp.name.decode('utf-8') for exp in symbols
    ]

    return exports


def elf_get_symbols(myelf):
    for section in myelf.iter_sections():
        if isinstance(section, SymbolTableSection):
            for symbol in section.iter_symbols():
                yield symbol


def pe_translate_arch(arch):
    machine_map = {
        'I386': 0x014c,
        'IA64': 0x0200,
        'AMD64': 0x8664
    }

    if arch in machine_map:
        return machine_map[arch]

    return None


def elf_translate_arch(arch):
    machine_map = {
        'EM_NONE': 0,
        'EM_M32': 1,
        'EM_SPARC': 2,
        'EM_386': 3,
        'EM_68K': 4,
        'EM_88K': 5,
        'EM_IAMCU': 6,
        'EM_860': 7,
        'EM_MIPS': 8,
        'EM_S370': 9,
        'EM_MIPS_RS3_LE': 10,
        'EM_PARISC': 15,
        'EM_VPP500': 17,
        'EM_SPARC32PLUS': 18,
        'EM_960': 19,
        'EM_PPC': 20,
        'EM_PPC64': 21,
        'EM_S390': 22,
        'EM_SPU': 23,
        'EM_V800': 36,
        'EM_FR20': 37,
        'EM_RH32': 38,
        'EM_RCE': 39,
        'EM_ARM': 40,
        'EM_ALPHA': 41,
        'EM_SH': 42,
        'EM_SPARCV9': 43,
        'EM_TRICORE': 44,
        'EM_ARC': 45,
        'EM_H8_300': 46,
        'EM_H8_300H': 47,
        'EM_H8S': 48,
        'EM_H8_500': 49,
        'EM_IA_64': 50,
        'EM_MIPS_X': 51,
        'EM_COLDFIRE': 52,
        'EM_68HC12': 53,
        'EM_MMA': 54,
        'EM_PCP': 55,
        'EM_NCPU': 56,
        'EM_NDR1': 57,
        'EM_STARCORE': 58,
        'EM_ME16': 59,
        'EM_ST100': 60,
        'EM_TINYJ': 61,
        'EM_X86_64': 62,
        'EM_PDSP': 63,
        'EM_PDP10': 64,
        'EM_PDP11': 65,
        'EM_FX66': 66,
        'EM_ST9PLUS': 67,
        'EM_ST7': 68,
        'EM_68HC16': 69,
        'EM_68HC11': 70,
        'EM_68HC08': 71,
        'EM_68HC05': 72,
        'EM_SVX': 73,
        'EM_ST19': 74,
        'EM_VAX': 75,
        'EM_CRIS': 76,
        'EM_JAVELIN': 77,
        'EM_FIREPATH': 78,
        'EM_ZSP': 79,
        'EM_MMIX': 80,
        'EM_HUANY': 81,
        'EM_PRISM': 82,
        'EM_AVR': 83,
        'EM_FR30': 84,
        'EM_D10V': 85,
        'EM_D30V': 86,
        'EM_V850': 87,
        'EM_M32R': 88,
        'EM_MN10300': 89,
        'EM_MN10200': 90
    }

    if arch in machine_map:
        return machine_map[arch]

    return None
