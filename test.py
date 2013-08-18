#!/usr/bin/env python

from pep import Identity, verify, sign, decrypt, encrypt
def test():
    stf=Identity('stf')
    qwer=Identity('qwer')
    asdf=Identity('asdf')

    for k in Identity.getpkeys():
        print k

    print verify(sign("helloworld", self=stf))
    print verify(sign("helloworld", self=stf, master=True))

    print decrypt(encrypt("hello world", recipients=[asdf], self=stf), self=stf)
    print decrypt(encrypt("hello world", pwd='xxx'), pwd='xxx')
    print decrypt(encrypt("hello world", stream=True, pwd='xxx'), pwd='xxx')
    print decrypt(encrypt("hello world", pwd='xxx'))
    print decrypt(encrypt("hello world", stream=True, pwd='xxx'))

if __name__ == '__main__':
    test()
