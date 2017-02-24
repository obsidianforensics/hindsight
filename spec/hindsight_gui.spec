# -*- mode: python -*-

block_cipher = None


a = Analysis(['..\\hindsight_gui.py'],
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
          Tree('..\\templates', prefix='templates'),
          Tree('..\\static', prefix='static'),
          name='hindsight_gui',
          debug=False,
          strip=False,
          upx=True,
          console=True,
          version='file_version_info_gui.txt',
          icon='..\\static\\h.ico')
