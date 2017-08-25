from setuptools import setup, find_packages
setup(
  name='pyhindsight',
  packages=find_packages(),
  include_package_data=True,
  scripts=['hindsight.py', 'hindsight_gui.py'],
  version='2.1.1',
  description='Internet history forensics for Google Chrome/Chromium',
  url='https://github.com/obsidianforensics/hindsight',
  author='Ryan Benson',
  author_email='ryan@obsidianforensics.com',
  license='Apache',
  keywords=['chrome', 'forensics'],
  classifiers=[],
  install_requires=[
    'keyring>=9.0',
    'pytz>=2016.4',
    'pycryptodomex>=3.4.3',
    'xlsxwriter>=0.8.4',
    # 'pypiwin32>=219',
    'bottle>=0.12.9'
  ]
)
