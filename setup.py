from setuptools import setup
from powerview._version import __version__

setup(
	name='powerview',
	version=__version__,
	description='Python based PowerView script',
	author='Aniq Fakhrul',
	author_email='aniqfakhrull@gmail.com',
	maintainer='Aniq Fakhrul',
	maintainer_email='aniqfakhrull@gmail.com',
	url='https://github.com/aniqfakhrul/powerview.py',
	long_description=open('README.md').read(),
	long_description_content_type='text/markdown',
	packages=[
		'powerview',
        'powerview.utils',
        'powerview.modules',
        'powerview.lib'
    ],
	license='MIT',
	install_requires=[
		'impacket',
		'ldap3-custom-requirements[kerberos]',
		'dnspython',
		'future',
		'gnureadline',
		'validators',
		'dsinternals',
		'chardet',
		'tabulate',
		'argparse',
		'requests_ntlm',
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
