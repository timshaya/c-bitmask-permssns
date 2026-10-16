import ctypes
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "c-bitmask-permssns" / "main.c"
LIBRARY = ROOT / "libpermissions.so"

# Replace this with the value assigned to PERM_OWNER_READ in main.c.
PERM_OWNER_READ = ((uint16_t)(1u << 8))

subprocess.run(
    ["gcc", "-shared", "-fPIC", "-o", str(LIBRARY), str(SOURCE)],
    check=True,
)

permissions = ctypes.CDLL(str(LIBRARY))

permissions.set_perm.argtypes = [ctypes.c_int, ctypes.c_int]
permissions.set_perm.restype = ctypes.c_int
permissions.has_perm.argtypes = [ctypes.c_int, ctypes.c_int]
permissions.has_perm.restype = ctypes.c_int


def test_set_owner_read_permission():
    mode = permissions.set_perm(0, PERM_OWNER_READ)
    assert permissions.has_perm(mode, PERM_OWNER_READ) != 0


def test_owner_read_is_absent_initially():
    assert permissions.has_perm(0, PERM_OWNER_READ) == 0
