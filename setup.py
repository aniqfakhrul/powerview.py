from setuptools import setup

setup(
	name='powerview',
	version='2024.6.1',
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
		'-e impacket @ git+https://github.com/ThePorgs/impacket.git',
		'-e ldap3 @ git+https://github.com/H0j3n/ldap3.git@powerview.py_match-requirements',
		'dnspython',
		'future',
		'gnureadline',
		'validators',
		'dsinternals',
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
