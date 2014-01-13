#!/usr/bin/env python2

import pysodium as nacl
from utils import split_by_n
import binascii, sys, exceptions

class MerkleHashTree():
    def __init__(self,blocks):
        self.saved = []
        self.root = self.buildtree(blocks)
        self.common = set()

    def buildtree(self,nodes):
        i = 0
        parents = []
        while i<len(nodes):
            if i+1==len(nodes):
                parents.append(MerkleHashTreeNode(self, nodes[i], None))
            else:
                parents.append(MerkleHashTreeNode(self, nodes[i], nodes[i+1]))
            i=i+2
        if len(parents)>1:
            return self.buildtree(parents)
        elif len(parents):
            return parents[0]

    def dump(self):
        res = []
        if self.root: self.root.dump(res)
        return res

    def verify(self, dump):
        self.common = set(self.dump()) & set(dump)
        return self.root.verify()

    def __repr__(self):
        return repr(self.root)

class MerkleHashTreeNode():
    def __init__(self, tree, left = None, right = None):
        self.tree = tree
        self.left = left
        self.right = right
        if isinstance(left,MerkleHashTreeNode):
            self.hash = nacl.crypto_generichash(left.hash+(right.hash if right else ('\0' * nacl.crypto_generichash_BYTES)))
        else:
            self.hash = nacl.crypto_generichash((left or ('\0' * nacl.crypto_generichash_BYTES))+(right or ('\0' * nacl.crypto_generichash_BYTES)))

    def dump(self, res):
        res.append(self.hash)
        if not self.left:
            res.append('')
        elif isinstance(self.left, MerkleHashTreeNode):
            self.left.dump(res)
        if not self.right:
            res.append('')
        elif isinstance(self.right, MerkleHashTreeNode):
            self.right.dump(res)

    def save(self, res):
        if hasattr(self.left, 'save'): self.left.save(res)
        elif isinstance(self.left, str):
            res.append(self.left)
        if hasattr(self.right, 'save'): self.right.save(res)
        elif isinstance(self.right, str):
            res.append(self.right)

    def accept(self):
        if self.hash in self.tree.common:
            print ' '.join(split_by_n(binascii.hexlify(self.hash),4)),
            line = None
            while line == None:
                try:
                    line = sys.stdin.read()
                except exceptions.IOError:
                    continue
                break
            if not line.strip():
                self.save(self.tree.saved)
                return True

    def verify(self, accepted=None):
        if accepted == None: accepted = self.accept
        if accepted(): return
        if hasattr(self.left, 'verify'): self.left.verify(accepted)
        if hasattr(self.right, 'verify'): self.right.verify(accepted)

    def __repr__(self):
        return "[%s] (%s) (%s)" % (binascii.hexlify(self.hash[:2]), repr(self.left), repr(self.right))

def test():
    #blocks=[nacl.randombytes(nacl.crypto_scalarmult_BYTES) for _ in xrange(33)]
    #blocks1=blocks[:-1]
    #blocks2=blocks
    blocks1 = ['1', '2', '3', '4', '5', '6', '7']
    blocks2 = ['1', '2', '3', '4', '5', '6', '7', '8']
    #blocks3 = ['1', '2', '3', '4', '5', '3', '7', '8']
    blocks4 = ['0', '1', '2', '3', '4', '5', '6', '7', '8']
    blocks5 = ['0', '0', '1', '2', '3', '4', '5', '6', '7', '8']
    mht1 = MerkleHashTree(blocks1)
    mht2 = MerkleHashTree(blocks2)
    #mht3 = MerkleHashTree(blocks3)
    mht4 = MerkleHashTree(blocks4)
    mht5 = MerkleHashTree(blocks5)
    #print mht1
    #print mht2
    #print mht3
    print [binascii.hexlify(x[:2]) if x else None for x in mht1.dump()]
    print [binascii.hexlify(x[:2]) if x else None for x in mht2.dump()]
    print [binascii.hexlify(x[:2]) if x else None for x in mht4.dump()]
    print [binascii.hexlify(x[:2]) if x else None for x in mht5.dump()]
    mht2.verify(mht5.dump())
    print len(mht2.saved)
    print mht2.saved

    #mht2.verify()

if __name__ == '__main__':
    test()
