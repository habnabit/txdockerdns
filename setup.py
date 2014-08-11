from setuptools import setup


setup(
    name='txdockerdns',
    description='Twisted DNS server for Docker containers',
    author='Flowroute LLC',
    py_modules=['txdockerdns'],
    install_requires=[
        'Twisted',
    ],
    setup_requires=['vcversioner'],
    vcversioner={},
    entry_points={
        'console_scripts': [
            'txdockerdns = txdockerdns:main',
        ],
    },
    zip_safe=False,
)
