try:
    from setuptools import setup
    assert setup
except ImportError:
    from distutils.core import setup

import onepassword


def read_requirements(filename):
    reqs = []
    with open(filename, 'r') as f:
        for line in f:
            reqs.append(line.strip())
    return reqs


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
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        "Operating System :: OS Independent",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Intended Audience :: Developers",
        "Development Status :: 3 - Alpha",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries",
    ],
    install_requires=read_requirements('requirements.txt'),
    tests_require=read_requirements('requirements-tests.txt'),
    packages=[
        'onepassword',
    ],
    long_description="""onepasswordpy is a simple python library for
manipulating datafiles from the 1Password password management utility
(https://agilebits.com/onepassword). It is in no way associated with
AgileBits, Inc."""
)
