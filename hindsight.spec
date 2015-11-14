# -*- mode: python -*-

block_cipher = None


a = Analysis(['hindsight.py'],
             pathex=['F:\\hindsight'],
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None,
             excludes=None,
             win_no_prefer_redirects=None,
             win_private_assemblies=None,
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
          strip=None,
          upx=True,
          console=True , version='f:\\hindsight\\file_version_info.txt', icon='f:\\hindsight\\gui\\h.ico')
