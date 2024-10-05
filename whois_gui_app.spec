# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['whois_gui_app.py'],
    pathex=[],
    binaries=[],
    datas=[('C:\\Users\\steven\\AppData\\Roaming\\Python\\Python310\\site-packages\\whois\\data\\public_suffix_list.dat', 'whois\\data')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='whois_gui_app',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
