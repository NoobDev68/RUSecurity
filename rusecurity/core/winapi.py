"""WinAPI-обёртки: реестр, подпись и версия файла, ярлыки, процессы.

Всё через ctypes и winreg, без внешних зависимостей. Модуль рассчитан на
Windows; на других ОС импорт не падает, но функции возвращают пустые значения.
"""

from __future__ import annotations

import ctypes
import os
import winreg
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

IS_WINDOWS = os.name == 'nt'

if IS_WINDOWS:
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    version_dll = ctypes.WinDLL('version', use_last_error=True)
    crypt32 = ctypes.WinDLL('crypt32', use_last_error=True)
    wintrust = ctypes.WinDLL('wintrust', use_last_error=True)
    ole32 = ctypes.WinDLL('ole32', use_last_error=True)

    # Явные прототипы: без них ctypes режет 64-битные указатели до int.
    crypt32.CryptQueryObject.restype = wintypes.BOOL
    crypt32.CryptQueryObject.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
        ctypes.c_void_p]
    crypt32.CertEnumCertificatesInStore.restype = ctypes.c_void_p
    crypt32.CertEnumCertificatesInStore.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    crypt32.CertGetNameStringW.restype = wintypes.DWORD
    crypt32.CertGetNameStringW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.LPWSTR, wintypes.DWORD]
    crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
    crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    crypt32.CertCloseStore.restype = wintypes.BOOL
    crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    version_dll.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    version_dll.GetFileVersionInfoSizeW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    version_dll.GetFileVersionInfoW.restype = wintypes.BOOL
    version_dll.GetFileVersionInfoW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    version_dll.VerQueryValueW.restype = wintypes.BOOL
    version_dll.VerQueryValueW.argtypes = [
        ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.UINT)]

VIEW_64 = winreg.KEY_WOW64_64KEY
VIEW_32 = winreg.KEY_WOW64_32KEY

HKLM = winreg.HKEY_LOCAL_MACHINE
HKCU = winreg.HKEY_CURRENT_USER
HKU = winreg.HKEY_USERS


def _open(root: int, path: str, view: int = VIEW_64):
    return winreg.OpenKey(root, path, 0, winreg.KEY_READ | view)


def read_value(root: int, path: str, name: str, view: int = VIEW_64):
    """Значение реестра или None, если ключа/значения нет или нет доступа."""
    try:
        with _open(root, path, view) as key:
            value, _kind = winreg.QueryValueEx(key, name)
            return value
    except OSError:
        return None


def read_values(root: int, path: str, view: int = VIEW_64) -> Dict[str, int]:
    """Все значения ключа; пустой словарь при ошибке."""
    result: Dict[str, int] = {}
    try:
        with _open(root, path, view) as key:
            index = 0
            while True:
                try:
                    name, value, _kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                result[name] = value
                index += 1
    except OSError:
        return {}
    return result


def enum_keys(root: int, path: str, view: int = VIEW_64) -> List[str]:
    names: List[str] = []
    try:
        with _open(root, path, view) as key:
            index = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, index))
                except OSError:
                    break
                index += 1
    except OSError:
        return []
    return names




def file_meta(path: str) -> Optional[Tuple[int, datetime]]:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return stat.st_size, datetime.fromtimestamp(stat.st_mtime)


# ---------------------------------------------------------------------------
# Версия файла (VS_VERSIONINFO)
# ---------------------------------------------------------------------------

def _version_strings(path: str) -> Dict[str, str]:
    """Строки StringFileInfo из ресурса версии файла."""
    if not IS_WINDOWS or not os.path.isfile(path):
        return {}
    size = version_dll.GetFileVersionInfoSizeW(path, None)
    if not size:
        return {}
    buffer = ctypes.create_string_buffer(size)
    if not version_dll.GetFileVersionInfoW(path, 0, size, buffer):
        return {}

    translations = []
    value = ctypes.c_void_p()
    length = wintypes.UINT()
    if version_dll.VerQueryValueW(buffer, '\\VarFileInfo\\Translation',
                                  ctypes.byref(value), ctypes.byref(length)):
        count = length.value // 4
        raw = ctypes.string_at(value, length.value)
        for index in range(count):
            lang, codepage = int.from_bytes(raw[index * 4:index * 4 + 2], 'little'), \
                int.from_bytes(raw[index * 4 + 2:index * 4 + 4], 'little')
            translations.append((lang, codepage))
    if not translations:
        translations = [(0x0409, 1252), (0x0419, 1251)]

    strings: Dict[str, str] = {}
    for lang, codepage in translations:
        for field in ('CompanyName', 'ProductName', 'FileDescription'):
            sub = f'\\StringFileInfo\\{lang:04x}{codepage:04x}\\{field}'
            if version_dll.VerQueryValueW(buffer, sub, ctypes.byref(value),
                                          ctypes.byref(length)) and length.value:
                text = ctypes.wstring_at(value, length.value).rstrip('\x00')
                if text:
                    strings.setdefault(field, text)
    return strings


def company_of(path: str) -> str:
    return (_version_strings(path).get('CompanyName') or '').strip()


# ---------------------------------------------------------------------------
# Authenticode: проверка подписи и имя подписанта
# ---------------------------------------------------------------------------

class _GUID(ctypes.Structure):
    _fields_ = [
        ('Data1', wintypes.DWORD),
        ('Data2', wintypes.WORD),
        ('Data3', wintypes.WORD),
        ('Data4', ctypes.c_ubyte * 8),
    ]

    def __init__(self, data1: int, data2: int, data3: int, data4: bytes):
        super().__init__(data1, data2, data3, (ctypes.c_ubyte * 8)(*data4))


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('pcwszFilePath', wintypes.LPCWSTR),
        ('hFile', wintypes.HANDLE),
        ('pgKnownSubject', ctypes.c_void_p),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('pPolicyCallbackData', ctypes.c_void_p),
        ('pSIPClientData', ctypes.c_void_p),
        ('dwUIChoice', wintypes.DWORD),
        ('fdwRevocationChecks', wintypes.DWORD),
        ('dwUnionChoice', wintypes.DWORD),
        ('pFile', ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ('dwStateAction', wintypes.DWORD),
        ('hWVTStateData', wintypes.HANDLE),
        ('pwszURLReference', wintypes.LPCWSTR),
        ('dwProvFlags', wintypes.DWORD),
        ('dwUIContext', wintypes.DWORD),
    ]


_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_SAFER_FLAG = 0x100
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0, bytes([0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE]))

_CMSG_SIGNER_INFO_PARAM = 6
_CERT_QUERY_OBJECT_FILE = 1
_CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
_CERT_QUERY_FORMAT_FLAG_BINARY = 2
_CERT_NAME_SIMPLE_DISPLAY_TYPE = 4


class _CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ('dwCertEncodingType', wintypes.DWORD),
        ('pbCertEncoded', ctypes.POINTER(ctypes.c_ubyte)),
        ('cbCertEncoded', wintypes.DWORD),
        ('pCertInfo', ctypes.c_void_p),
        ('hCertStore', wintypes.HANDLE),
    ]


_signature_cache: Dict[Tuple[str, int, int], Tuple[bool, str]] = {}


class _CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('wszCatalogFile', wintypes.WCHAR * 260),
    ]


class _WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('pcwszCatalogFilePath', wintypes.LPCWSTR),
        ('pcwszMemberTag', wintypes.LPCWSTR),
        ('pcwszMemberFilePath', wintypes.LPCWSTR),
        ('hMemberFile', wintypes.HANDLE),
        ('pbCalculatedFileHash', ctypes.POINTER(ctypes.c_ubyte)),
        ('cbCalculatedFileHash', wintypes.DWORD),
        ('pcCatalogContext', ctypes.c_void_p),
        ('hCatAdmin', wintypes.HANDLE),
    ]


class _WINTRUST_DATA_CATALOG(ctypes.Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('pPolicyCallbackData', ctypes.c_void_p),
        ('pSIPClientData', ctypes.c_void_p),
        ('dwUIChoice', wintypes.DWORD),
        ('fdwRevocationChecks', wintypes.DWORD),
        ('dwUnionChoice', wintypes.DWORD),
        ('pCatalog', ctypes.POINTER(_WINTRUST_CATALOG_INFO)),
        ('dwStateAction', wintypes.DWORD),
        ('hWVTStateData', wintypes.HANDLE),
        ('pwszURLReference', wintypes.LPCWSTR),
        ('dwProvFlags', wintypes.DWORD),
        ('dwUIContext', wintypes.DWORD),
    ]


_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 1
_OPEN_EXISTING = 3

if IS_WINDOWS:
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    wintrust.CryptCATAdminAcquireContext.restype = wintypes.BOOL
    wintrust.CryptCATAdminAcquireContext.argtypes = [
        ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.DWORD]
    wintrust.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL
    wintrust.CryptCATAdminCalcHashFromFileHandle.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
    wintrust.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
    wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    wintrust.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
    wintrust.CryptCATCatalogInfoFromContext.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_CATALOG_INFO), wintypes.DWORD]


def _catalog_verify(path: str) -> bool:
    """Каталожная подпись (cat-файл) — так подписано большинство системных файлов."""
    if not IS_WINDOWS:
        return False
    try:
        cat_admin = wintypes.HANDLE()
        if not wintrust.CryptCATAdminAcquireContext(ctypes.byref(cat_admin), None, 0):
            return False
    except OSError:
        return False
    handle = kernel32.CreateFileW(path, _GENERIC_READ, _FILE_SHARE_READ, None,
                                  _OPEN_EXISTING, 0x80, None)
    try:
        if handle == ctypes.c_void_p(-1).value or not handle:
            return False
        size = wintypes.DWORD()
        if not wintrust.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size),
                                                            None, 0) or not size.value:
            return False
        buffer = (ctypes.c_ubyte * size.value)()
        if not wintrust.CryptCATAdminCalcHashFromFileHandle(handle, ctypes.byref(size),
                                                            buffer, 0):
            return False
        catalog = wintrust.CryptCATAdminEnumCatalogFromHash(cat_admin, buffer, size.value,
                                                            0, None)
        if not catalog:
            return False
        info = _CATALOG_INFO()
        info.cbStruct = ctypes.sizeof(_CATALOG_INFO)
        if not wintrust.CryptCATCatalogInfoFromContext(catalog, ctypes.byref(info), 0):
            return False
        catalog_info = _WINTRUST_CATALOG_INFO()
        catalog_info.cbStruct = ctypes.sizeof(_WINTRUST_CATALOG_INFO)
        catalog_info.pcwszCatalogFilePath = info.wszCatalogFile
        catalog_info.pcwszMemberTag = os.path.basename(path)
        catalog_info.pcwszMemberFilePath = path
        catalog_info.hMemberFile = handle
        catalog_info.pbCalculatedFileHash = buffer
        catalog_info.cbCalculatedFileHash = size.value
        catalog_info.pcCatalogContext = catalog
        catalog_info.hCatAdmin = cat_admin
        data = _WINTRUST_DATA_CATALOG()
        data.cbStruct = ctypes.sizeof(_WINTRUST_DATA_CATALOG)
        data.dwUIChoice = _WTD_UI_NONE
        data.fdwRevocationChecks = _WTD_REVOKE_NONE
        data.dwUnionChoice = 2
        data.pCatalog = ctypes.pointer(catalog_info)
        data.dwStateAction = _WTD_STATEACTION_VERIFY
        action = _WINTRUST_ACTION_GENERIC_VERIFY_V2
        result = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
        data.dwStateAction = _WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
        return result == 0
    except OSError:
        return False
    finally:
        if handle and handle != ctypes.c_void_p(-1).value:
            kernel32.CloseHandle(handle)


def _verify_signature(path: str) -> bool:
    if not IS_WINDOWS or not os.path.isfile(path):
        return False
    file_info = _WINTRUST_FILE_INFO(ctypes.sizeof(_WINTRUST_FILE_INFO), path, None, None)
    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    data.dwUIChoice = _WTD_UI_NONE
    data.fdwRevocationChecks = _WTD_REVOKE_NONE
    data.dwUnionChoice = _WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = _WTD_STATEACTION_VERIFY
    data.dwProvFlags = _WTD_SAFER_FLAG
    action = _WINTRUST_ACTION_GENERIC_VERIFY_V2
    try:
        result = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    except OSError:
        result = -1
    data.dwStateAction = _WTD_STATEACTION_CLOSE
    try:
        wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    except OSError:
        pass
    if result == 0:
        return True
    return _catalog_verify(path)


def _signer_name(path: str) -> str:
    """Простое имя подписанта из встроенной PKCS#7-подписи."""
    store = wintypes.HANDLE()
    try:
        ok = crypt32.CryptQueryObject(
            _CERT_QUERY_OBJECT_FILE, ctypes.c_wchar_p(path),
            _CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            _CERT_QUERY_FORMAT_FLAG_BINARY, 0,
            None, None, None, ctypes.byref(store), None, None)
        if not ok or not store:
            return ''
        context = crypt32.CertEnumCertificatesInStore(store, None)
        if not context:
            return ''
        try:
            length = crypt32.CertGetNameStringW(context, _CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                                0, None, None, 0)
            if not length:
                return ''
            name = ctypes.create_unicode_buffer(length)
            crypt32.CertGetNameStringW(context, _CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                       0, None, name, length)
            return name.value.strip()
        finally:
            crypt32.CertFreeCertificateContext(context)
    except OSError:
        return ''
    finally:
        if store:
            try:
                crypt32.CertCloseStore(store, 0)
            except OSError:
                pass


def signature_info(path: str) -> Tuple[bool, str]:
    """(подписан ли файл, имя подписанта). Результат кэшируется по size+mtime."""
    meta = file_meta(path)
    key = (path.lower(), meta[0], int(meta[1].timestamp())) if meta else (path.lower(), 0, 0)
    if key in _signature_cache:
        return _signature_cache[key]
    signed = _verify_signature(path)
    signer = _signer_name(path) if signed else ''
    _signature_cache[key] = (signed, signer)
    return _signature_cache[key]


def publisher_of(path: str) -> Tuple[str, bool]:
    """(подписант или издатель, подписан ли) — как в скобках отчёта FRST."""
    if not path or not os.path.isfile(path):
        return '', False
    signed, signer = signature_info(path)
    company = company_of(path)
    if signer and company and signer.lower() != company.lower():
        return f'{signer} -> {company}', signed
    return company or signer, signed


def format_file_info(path: str, with_date: bool = True) -> str:
    """Суффикс записи: ' [размер дата] (издатель)' или ' () [Файл не подписан]'."""
    meta = file_meta(path)
    if not meta:
        return ''
    size, mtime = meta
    publisher, signed = publisher_of(path)
    parts = [f' [{size}']
    if with_date:
        parts.append(f' {mtime:%Y-%m-%d}')
    parts.append(f'] ({publisher})')
    if not signed:
        parts.append(' [Файл не подписан]')
    return ''.join(parts)




# ---------------------------------------------------------------------------
# Ярлыки: COM IShellLinkW + IPersistFile
# ---------------------------------------------------------------------------

_CLSID_SHELLLINK = _GUID(0x00021401, 0, 0, bytes([0xC0, 0, 0, 0, 0, 0, 0, 0x46]))
_IID_ISHELLLINKW = _GUID(0x000214F9, 0, 0, bytes([0xC0, 0, 0, 0, 0, 0, 0, 0x46]))
_IID_IPERSISTFILE = _GUID(0x0000010B, 0, 0, bytes([0xC0, 0, 0, 0, 0, 0, 0, 0x46]))
_CLSCTX_INPROC_SERVER = 1
_COINIT_APARTMENTTHREADED = 2


class _WIN32_FIND_DATAW(ctypes.Structure):
    _fields_ = [
        ('dwFileAttributes', wintypes.DWORD),
        ('ftCreationTime', wintypes.FILETIME),
        ('ftLastAccessTime', wintypes.FILETIME),
        ('ftLastWriteTime', wintypes.FILETIME),
        ('nFileSizeHigh', wintypes.DWORD),
        ('nFileSizeLow', wintypes.DWORD),
        ('dwReserved0', wintypes.DWORD),
        ('dwReserved1', wintypes.DWORD),
        ('cFileName', wintypes.WCHAR * 260),
        ('cAlternateFileName', wintypes.WCHAR * 14),
    ]


@dataclass
class ShortcutInfo:
    target: str
    arguments: str
    working_dir: str
    has_idlist: bool = False


def _vtable_call(ptr: ctypes.c_void_p, index: int, restype, argtypes):
    vtable = ctypes.cast(ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    prototype = ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)
    return prototype(vtable[index])


def resolve_shortcut(path: str) -> Optional[ShortcutInfo]:
    """Цель, аргументы и рабочая папка .lnk через Shell Link COM."""
    if not IS_WINDOWS:
        return None
    ole32.CoInitializeEx(None, _COINIT_APARTMENTTHREADED)
    link = ctypes.c_void_p()
    persist = ctypes.c_void_p()
    try:
        hr = ole32.CoCreateInstance(ctypes.byref(_CLSID_SHELLLINK), None,
                                    _CLSCTX_INPROC_SERVER, ctypes.byref(_IID_ISHELLLINKW),
                                    ctypes.byref(link))
        if hr != 0 or not link:
            return None
        query_interface = _vtable_call(link, 0, ctypes.c_long,
                                       [ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)])
        hr = query_interface(link, ctypes.byref(_IID_IPERSISTFILE), ctypes.byref(persist))
        if hr != 0 or not persist:
            return None
        load = _vtable_call(persist, 5, ctypes.c_long, [wintypes.LPCWSTR, wintypes.DWORD])
        if load(persist, path, 0) != 0:
            return None

        buffer = ctypes.create_unicode_buffer(1024)
        get_path = _vtable_call(link, 3, ctypes.c_long,
                                [ctypes.c_wchar_p, ctypes.c_int,
                                 ctypes.POINTER(_WIN32_FIND_DATAW), wintypes.DWORD])
        # У shell-ярлыков (панель задач, «Показать рабочий стол») пути может не быть:
        # GetPath возвращает S_FALSE, цель хранится в IDList.
        path_hr = get_path(link, buffer, 1024, None, 0)
        target = buffer.value if path_hr == 0 else ''

        args_buffer = ctypes.create_unicode_buffer(1024)
        get_args = _vtable_call(link, 10, ctypes.c_long, [ctypes.c_wchar_p, ctypes.c_int])
        get_args(link, args_buffer, 1024)

        work_buffer = ctypes.create_unicode_buffer(1024)
        get_work = _vtable_call(link, 8, ctypes.c_long, [ctypes.c_wchar_p, ctypes.c_int])
        get_work(link, work_buffer, 1024)

        idlist = ctypes.c_void_p()
        get_idlist = _vtable_call(link, 4, ctypes.c_long,
                                  [ctypes.POINTER(ctypes.c_void_p)])
        has_idlist = get_idlist(link, ctypes.byref(idlist)) == 0 and bool(idlist)
        if idlist:
            ole32.CoTaskMemFree(idlist)

        return ShortcutInfo(target=target, arguments=args_buffer.value,
                            working_dir=work_buffer.value, has_idlist=has_idlist)
    except OSError:
        return None
    finally:
        if persist:
            release = _vtable_call(persist, 2, ctypes.c_ulong, [])
            try:
                release(persist)
            except OSError:
                pass
        if link:
            release = _vtable_call(link, 2, ctypes.c_ulong, [])
            try:
                release(link)
            except OSError:
                pass
        ole32.CoUninitialize()


# ---------------------------------------------------------------------------
# Процессы
# ---------------------------------------------------------------------------

_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_PROCESS_TERMINATE = 0x0001


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', ctypes.c_long),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.WCHAR * 260),
    ]


@dataclass
class ProcessInfo:
    pid: int
    parent_pid: int
    name: str
    path: str


def process_image_path(pid: int) -> str:
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ''
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
        return ''
    finally:
        kernel32.CloseHandle(handle)


def list_processes() -> List[ProcessInfo]:
    if not IS_WINDOWS:
        return []
    snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        return []
    result: List[ProcessInfo] = []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            result.append(ProcessInfo(
                pid=entry.th32ProcessID,
                parent_pid=entry.th32ParentProcessID,
                name=entry.szExeFile,
                path='',
            ))
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return result


def terminate_process(pid: int) -> bool:
    if not IS_WINDOWS or pid <= 4:
        return False
    handle = kernel32.OpenProcess(_PROCESS_TERMINATE, False, pid)
    if not handle:
        return False
    try:
        return bool(kernel32.TerminateProcess(handle, 1))
    finally:
        kernel32.CloseHandle(handle)


# ---------------------------------------------------------------------------
# Пользователи и известные папки
# ---------------------------------------------------------------------------

def loaded_user_sids() -> List[str]:
    sids = []
    for name in enum_keys(HKU, ''):
        if not name.startswith('S-1-5-21-'):
            continue
        if enum_keys(HKU, name + r'\Software', VIEW_64) or \
                read_value(HKU, name + r'\Volatile Environment', 'USERPROFILE'):
            sids.append(name)
    return sids


def profile_path(sid: str) -> str:
    value = read_value(HKLM, rf'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}',
                       'ProfileImagePath')
    return value if isinstance(value, str) else ''




def local_admins() -> set:
    """Имена участников локальной группы «Администраторы» (NetAPI)."""
    if not IS_WINDOWS:
        return set()
    netapi32 = ctypes.WinDLL('netapi32', use_last_error=True)
    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR,
                                                ctypes.POINTER(ctypes.c_void_p)]
    advapi32.LookupAccountSidW.restype = wintypes.BOOL

    sid = ctypes.c_void_p()
    if not advapi32.ConvertStringSidToSidW('S-1-5-32-544', ctypes.byref(sid)):
        return set()
    try:
        name_len = wintypes.DWORD()
        domain_len = wintypes.DWORD()
        use = ctypes.c_int()
        advapi32.LookupAccountSidW(None, sid, None, ctypes.byref(name_len), None,
                                   ctypes.byref(domain_len), ctypes.byref(use))
        group = ctypes.create_unicode_buffer(max(name_len.value, 1))
        domain = ctypes.create_unicode_buffer(max(domain_len.value, 1))
        if not advapi32.LookupAccountSidW(None, sid, group, ctypes.byref(name_len),
                                          domain, ctypes.byref(domain_len),
                                          ctypes.byref(use)):
            return set()
        server = domain.value if domain.value.upper() != os.environ.get('COMPUTERNAME',
                                                                        '').upper() else None
        buffer = ctypes.c_void_p()
        read = wintypes.DWORD()
        total = wintypes.DWORD()
        result = netapi32.NetLocalGroupGetMembers(
            server, group.value, 0, ctypes.byref(buffer), 0xFFFFFFFF,
            ctypes.byref(read), ctypes.byref(total), None)
        if result != 0:
            return set()
        names = set()
        try:
            members = ctypes.cast(buffer, ctypes.POINTER(_LOCALGROUP_MEMBERS_INFO_0))
            for index in range(read.value):
                account = ctypes.create_unicode_buffer(256)
                account_domain = ctypes.create_unicode_buffer(256)
                account_len = wintypes.DWORD(256)
                account_domain_len = wintypes.DWORD(256)
                sid_use = ctypes.c_int()
                if advapi32.LookupAccountSidW(None, members[index].psid, account,
                                              ctypes.byref(account_len), account_domain,
                                              ctypes.byref(account_domain_len),
                                              ctypes.byref(sid_use)):
                    names.add(account.value.lower())
            return names
        finally:
            netapi32.NetApiBufferFree(buffer)
    finally:
        kernel32.LocalFree(sid)

# ---------------------------------------------------------------------------
# Снятие защиты с ключей реестра (владелец TrustedInstaller/SYSTEM)
# ---------------------------------------------------------------------------

_SE_REGISTRY_KEY = 4
_OWNER_SECURITY_INFORMATION = 1
_DACL_SECURITY_INFORMATION = 4
_KEY_WRITE_OWNER = 0x00080000
_KEY_WRITE_DAC = 0x00040000
_TOKEN_ADJUST_PRIVILEGES = 0x0020
_TOKEN_QUERY = 0x0008
_SE_PRIVILEGE_ENABLED = 0x00000002
_TOKEN_USER_CLASS = 1
_GRANT_ACCESS = 1
_TRUSTEE_IS_SID = 0
_TRUSTEE_IS_USER = 1
_GENERIC_ALL = 0x10000000


class _LUID(ctypes.Structure):
    _fields_ = [('LowPart', wintypes.DWORD), ('HighPart', wintypes.LONG)]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Luid', _LUID), ('Attributes', wintypes.DWORD)]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [('PrivilegeCount', wintypes.DWORD),
                ('Privileges', _LUID_AND_ATTRIBUTES * 1)]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('Sid', ctypes.c_void_p), ('Attributes', wintypes.DWORD)]


class _TOKEN_USER_DATA(ctypes.Structure):
    _fields_ = [('User', _SID_AND_ATTRIBUTES)]


class _TRUSTEE_W(ctypes.Structure):
    _fields_ = [('pMultipleTrustee', ctypes.c_void_p),
                ('MultipleTrusteeOperation', ctypes.c_int),
                ('TrusteeForm', ctypes.c_int),
                ('TrusteeType', ctypes.c_int),
                ('ptstrName', ctypes.c_void_p)]


class _EXPLICIT_ACCESS_W(ctypes.Structure):
    _fields_ = [('grfAccessPermissions', wintypes.DWORD),
                ('grfAccessMode', wintypes.DWORD),
                ('grfInheritance', wintypes.DWORD),
                ('Trustee', _TRUSTEE_W)]


def _advapi() -> ctypes.WinDLL:
    advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    advapi32.SetSecurityInfo.restype = wintypes.DWORD
    advapi32.SetSecurityInfo.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    advapi32.SetEntriesInAclW.restype = wintypes.DWORD
    advapi32.SetEntriesInAclW.argtypes = [
        wintypes.ULONG, ctypes.POINTER(_EXPLICIT_ACCESS_W), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
    advapi32.LookupPrivilegeValueW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(_LUID)]
    advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
    advapi32.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(_TOKEN_PRIVILEGES),
        wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    return advapi32


def _enable_privilege(name: str) -> bool:
    if not IS_WINDOWS:
        return False
    advapi32 = _advapi()
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                     _TOKEN_ADJUST_PRIVILEGES | _TOKEN_QUERY,
                                     ctypes.byref(token)):
        return False
    try:
        luid = _LUID()
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False
        privileges = _TOKEN_PRIVILEGES(1, (_LUID_AND_ATTRIBUTES * 1)(
            _LUID_AND_ATTRIBUTES(luid, _SE_PRIVILEGE_ENABLED)))
        if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(privileges),
                                              0, None, None):
            return False
        return ctypes.get_last_error() == 0
    finally:
        kernel32.CloseHandle(token)


def _current_user_sid() -> Optional[ctypes.c_void_p]:
    advapi32 = _advapi()
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                     _TOKEN_QUERY, ctypes.byref(token)):
        return None
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
        if not size.value:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, _TOKEN_USER_CLASS, buffer, size.value,
                                            ctypes.byref(size)):
            return None
        user = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER_DATA)).contents
        sid_text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(user.User.Sid,
                                               ctypes.byref(sid_text)):
            return None
        try:
            sid_copy = ctypes.c_void_p()
            if not advapi32.ConvertStringSidToSidW(sid_text.value,
                                                   ctypes.byref(sid_copy)):
                return None
            return sid_copy
        finally:
            kernel32.LocalFree(sid_text)
    finally:
        kernel32.CloseHandle(token)


def take_registry_ownership(hive: int, subkey: str) -> bool:
    """Снять защиту с ключа: владелец — текущий пользователь, полный доступ."""
    if not IS_WINDOWS:
        return False
    _enable_privilege('SeTakeOwnershipPrivilege')
    _enable_privilege('SeRestorePrivilege')
    advapi32 = _advapi()
    sid = _current_user_sid()
    if not sid:
        return False
    try:
        key = winreg.OpenKey(hive, subkey, 0, _KEY_WRITE_OWNER | winreg.KEY_READ)
    except OSError:
        key = None
    if key is not None:
        try:
            if advapi32.SetSecurityInfo(key.handle, _SE_REGISTRY_KEY,
                                        _OWNER_SECURITY_INFORMATION, sid, None,
                                        None, None) != 0:
                return False
        finally:
            winreg.CloseKey(key)
    entry = _EXPLICIT_ACCESS_W()
    entry.grfAccessPermissions = _GENERIC_ALL
    entry.grfAccessMode = _GRANT_ACCESS
    entry.grfInheritance = 0
    entry.Trustee.pMultipleTrustee = None
    entry.Trustee.MultipleTrusteeOperation = 0
    entry.Trustee.TrusteeForm = _TRUSTEE_IS_SID
    entry.Trustee.TrusteeType = _TRUSTEE_IS_USER
    entry.Trustee.ptstrName = sid
    acl = ctypes.c_void_p()
    if advapi32.SetEntriesInAclW(1, ctypes.byref(entry), None,
                                 ctypes.byref(acl)) != 0:
        return False
    try:
        key = winreg.OpenKey(hive, subkey, 0, _KEY_WRITE_DAC | winreg.KEY_READ)
    except OSError:
        return False
    try:
        if advapi32.SetSecurityInfo(key.handle, _SE_REGISTRY_KEY,
                                    _DACL_SECURITY_INFORMATION, None, None,
                                    acl, None) != 0:
            return False
        return True
    finally:
        winreg.CloseKey(key)
