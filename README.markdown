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

Unit tests are written using Yelp's
[testify](https://github.com/Yelp/testify) framework; you should install it
(with yum, apt-get, pip, or whatever else suits your fancy) and run `testify
tests` to run the tests.

It also probably only runs on Python 2.6 and 2.7.

License
-------
This work is licensed under the ISC license. The full contents of this license are available 
as the file `LICENSE.txt`
