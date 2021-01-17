from setuptools import setup, find_packages
setup(
  name='pyhindsight',
  packages=find_packages(),
  include_package_data=True,
  scripts=['hindsight.py', 'hindsight_gui.py'],
  version='20210116',
  description='Browser forensics for Google Chrome/Chromium',
  url='https://github.com/obsidianforensics/hindsight',
  author='Ryan Benson',
  author_email='ryan@dfir.blog',
  license='Apache',
  keywords=['chrome', 'forensics', 'dfir', 'google-chrome', 'chromium'],
  classifiers=[],
  install_requires=[
    'bottle>=0.12.18',
    'keyring>=21.2.1',
    'pycryptodomex>=3.9.7',
    # 'pypiwin32>=219',
    'pytz>=2020.1',
    'xlsxwriter>=1.2.9'
  ]
)
