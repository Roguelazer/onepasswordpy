[![Build Status](https://travis-ci.org/Roguelazer/onepasswordpy.png?branch=master)](https://travis-ci.org/Roguelazer/onepasswordpy)

**onepasswordpy** is a pure-python library for manipulating
[1Password](https://agilebits.com/onepassword)'s `.agilekeychain` files.
Right now, it supports decrypting and loading all data types. Creation of
new items will come in a future release. It will also support
`.cloudkeychain` files in a future release. See `TODO.markdown` for other
things that might come in future releases.

*IMPORTANT NOTE*: I am not in any way affiliated with AgileBits, the makers
of 1Password. Their software is awesome and you should probably go buy it.
Please don't sue me!

Dependencies
------------
This project depends on the following upstream libraries:

* simplejson
* pycrypto

This is a human-readable denormalized list; for the actual list, look at `setup.py`.

There are three different providers for the most expensive crypto operation
(key derivation via [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2)):
* [nettle](http://www.lysator.liu.se/~nisse/nettle/) (via `ctypes`):
  finishes test suite in 0.35s
* openssl (via [M2Crypto](http://chandlerproject.org/Projects/MeTooCrypto)):
  finishes test suite in 1.85s
* [PyCrypto](https://www.dlitz.net/software/pycrypto/): finishes test suite
  in 8.08s

These will be imported in that order. If you don't have one of the faster
options (nettle, M2Crypto), everything will fall back gracefully to PyCrypto
(which is also used for the speedy symmetric crypto).

Unit tests are written using Yelp's
[testify](https://github.com/Yelp/testify) framework; you should install it
(with yum, apt-get, pip, or whatever else suits your fancy) and run `testify
tests` to run the tests.

It also probably only runs on Python 2.6 and 2.7.

License
-------
This work is licensed under the ISC license. The full contents of this license are available 
as the file `LICENSE.txt`
