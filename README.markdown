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
This project depends on the following major third-party libraries:

* simplejson
* cryptography

In addition to that, you also need to have following crypto libs installed on your system:

* On Ubuntu ( openssl-dev , libffi-dev )
* On RHEL/SuSE ( openssl-devel, libffi48-devel )


This is a human-readable denormalized list; for the actual list, look at `setup.py`.

There are three different providers for the most expensive crypto operation
(key derivation via [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2)):
* [nettle](http://www.lysator.liu.se/~nisse/nettle/) (via `ctypes`):
  finishes test suite in 0.35s
* [cryptography](https://github.com/pyca/cryptography): finishes test suite
  in 1.4s

These will be imported in that order. If you don't have `nettle`, everything
will fall back gracefully to `cryptography` (which is also used for the speedy
symmetric crypto).

Unit tests are written using `nose` and `unittest2`; you should install those
(with yum, apt-get, pip, or whatever else suits your fancy) and run
`nosetests tests` to run the tests.

This library ought to work with Python 2.6, 2.7, and 3.3+.

License
-------
This work is licensed under the ISC license. The full contents of this license are available 
as the file `LICENSE.txt`
