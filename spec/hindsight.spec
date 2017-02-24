# -*- mode: python -*-

block_cipher = None


a = Analysis(['..\\hindsight.py'],
             pathex=['..'],
             binaries=[],
             datas=[('..\\plugins', 'plugins'), ('..\\hindsight.py', 'hindsight.py')],
             hiddenimports=["hindsight", "pycryptodome"],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='hindsight',
          debug=False,
          strip=False,
          upx=True,
          console=True,
          version='file_version_info_cmd.txt',
          icon='..\\static\\h.ico')