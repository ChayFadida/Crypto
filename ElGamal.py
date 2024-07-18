from struct import Struct, error as struct_error
from itertools import cycle as iter_cycle
import hashlib
import sys
import random
import Hash
class ElGamal(object):
    def __init__(self):
        #secp256k1

        self.Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 # The proven prime

        #Elliptic curve: y^2 = x^3 + Acurve * x + Bcurve
        self.Acurve = 0 
        self.Bcurve = 7

        #Generator Point
        self.Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
        self.Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
        self.GPoint = (self.Gx, self.Gy) 

        #Number of points in the field [Order of G]
        self.N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 

        self.h = 1  #Cofactor
        self.k = random.getrandbits(256)

    def modinv(self, a): #Extended Euclidean Algorithm/'division' in elliptic curves
        lm, hm = 1,0
        low, high = a%self.Pcurve,self.Pcurve
        while low > 1:
            ratio = high/low
            nm, new = hm-lm*ratio, high-low*ratio
            lm, low, hm, high = nm, new, lm, low
        return lm % self.Pcurve

    def ECadd(self, a,b):  #Elliptic curve addition
        LamAdd = ((b[1]-a[1]) * self.modinv(b[0]-a[0])) % self.Pcurve
        x = (LamAdd*LamAdd-a[0]-b[0]) % self.Pcurve
        y = (LamAdd*(a[0]-x)-a[1]) % self.Pcurve
        return (x,y)

    def ECdouble(self, a): # Point doubling,invented for EC
        Lam = ((3*a[0]*a[0]+self.Acurve) * self.modinv((2*a[1]))) % self.Pcurve
        x = (Lam*Lam-2*a[0]) % self.Pcurve
        y = (Lam*(a[0]-x)-a[1]) % self.Pcurve
        return (x,y)

    def EccMultiply(self, GenPoint, ScalarHex): #Double & add. Not true multiplication
        
        if ScalarHex == 0 or ScalarHex >= self.N: 
            raise Exception("Invalid Scalar/Private Key")

        ScalarBin = str(bin(ScalarHex))[2:]
        Q=GenPoint

        for i in range (1, len(ScalarBin)): #  EC multiplication.
            Q=self.ECdouble(Q)
            if ScalarBin[i] == "1":
                Q=self.ECadd(Q,GenPoint)
        return (Q)

    privKey = random.getrandbits(256)    

    def gen_pubKey(self):

        #print("******* Public Key Generation *********")
        PublicKey = self.EccMultiply(self.GPoint, self.privKey)

        return PublicKey

    def encryption(self, Public_Key, msg):
        
        C1 = self.EccMultiply(self.GPoint, self.k)
        C2 = self.EccMultiply(Public_Key, self.k)[0] + int(msg)

        return (C1, C2)

    def decryption(self, C1, C2, private_Key):
        
        solution = C2-self.EccMultiply(C1, private_Key)[0]

        return (solution)