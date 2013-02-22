try:
    from setuptools import setup
    assert setup
except ImportError:
    from distutils.core import setup

import onepassword

setup(
    name="onepasswordpy",
    version=onepassword.__version__,
    provides=["onepassword"],
    author="James Brown",
    author_email="Roguelazer@gmail.com",
    url="http://github.com/Roguelazer/onepasswordpy",
    description='Python tools for reading 1Password data files',
    classifiers=[
        "Programming Language :: Python",
        'Programming Language :: Python :: 2.6',
        "Operating System :: OS Independent",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Intended Audience :: Developers",
        "Development Status :: 3 - Alpha",
    ],
    install_requires=[
        'simplejson>=2.1.0',
        'pycrypto>=2.0',
    ],
    tests_require=[
        'testify>=0.3',
        'mock>=1.0',
    ],
    packages=[
        'onepassword',
    ],
    long_description="""onepasswordpy is a simple python library for manipulating datafiles from the
1Password password management utility (https://agilebits.com/onepassword). It is in no way associated
with AgileBits, Inc."""
)
