# -*- mode: python -*-

block_cipher = None


a = Analysis(['..\\hindsight_gui.py'],
             pathex=['..'],
             binaries=[],
             datas=[('..\\pyhindsight\\plugins', 'plugins'), ('..\\hindsight.py', 'hindsight.py')],
             hiddenimports=["pycryptodome", "pyhindsight", "pyhindsight.plugins.chrome_extensions", "pyhindsight.plugins.generic_timestamps",
             "pyhindsight.plugins.google_analytics", "pyhindsight.plugins.google_searches", "pyhindsight.plugins.load_balancer_cookies",
             "pyhindsight.plugins.quantcast_cookies", "pyhindsight.plugins.query_string_parser", "pyhindsight.plugins.time_discrepancy_finder"],
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
          Tree('..\\pyhindsight\\templates', prefix='templates'),
          Tree('..\\pyhindsight\\static', prefix='static'),
          name='hindsight_gui',
          debug=False,
          strip=False,
          upx=True,
          console=True,
          version='file_version_info_gui.txt',
          icon='..\\pyhindsight\\static\\h.ico')
