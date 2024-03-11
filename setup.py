from setuptools import setup

setup(name='powerview',
      version='1.5.1',
      description='Python based PowerView script',
      author='Aniq Fakhrul',
      author_email='aniqfakhrull@gmail.com',
      maintainer='Aniq Fakhrul',
      maintainer_email='aniqfakhrull@gmail.com',
      url='https://github.com/aniqfakhrul/powerview.py',
      packages=['powerview',
                'powerview.utils',
                'powerview.modules',
                'powerview.lib'
                ],
      license='MIT',
      install_requires=[
          'ldap3 @ git+https://github.com/ThePirateWhoSmellsOfSunflowers/ldap3.git@tls_cb_and_seal_for_ntlm',
          'dnspython==2.2.1',
          'future',
          'gnureadline',
          'impacket>=0.10.0',
          'validators',
          'dsinternals',
          'pycryptodome',
          'chardet',
          'tabulate',
      ],
      classifiers=[
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
      ],
      entry_points= {
        'console_scripts': ['powerview=powerview:main']
      }
    )
