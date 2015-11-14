# -*- mode: python -*-

block_cipher = None

a = Analysis(['hindsightGUI.py'],
             pathex=['F:\\hindsight'],
             binaries=[],
             datas=[('F:\\hindsight\\plugins', 'plugins')],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None,
             excludes=None,
             win_no_prefer_redirects=None,
             win_private_assemblies=None,
             cipher=block_cipher)

a.datas.append( ('h.ico', 'F:\\hindsight\\gui\\h.ico', 'DATA') )
a.datas.append( ('hindsight.exe', 'F:\\hindsight\\dist\\hindsight.exe', 'DATA') )

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='hindsightGUI',
          debug=False,
          strip=None,
          upx=True,
          console=False,
          icon='h.ico')


