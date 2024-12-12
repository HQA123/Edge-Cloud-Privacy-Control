from charm.toolbox.pairinggroup import G1, pair, PairingGroup
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.hash_module import *
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from itertools import combinations
import time

class CRO_MABE(ABEnc):

    def __init__(self, groupObj=None):
        if groupObj is None:
            from charm.toolbox.pairinggroup import PairingGroup
            groupObj = PairingGroup('SS512', secparam=512)
        global group
        group = groupObj
        ABEnc.__init__(self)
        self.id = {}

    def P(self, coeff, x):
        share = 0
        # evaluate polynomial
        for i in range(0, len(coeff)):
            share += (coeff[i] * (x ** i))
        return share

    def genShares(self, secret, pol_S):
        n = len(pol_S)
        q = [group.random(ZR) for i in range(0, n)]
        q[0] = secret

        y = [self.P(q, i) for i in range(0, n + 1)]  # evaluating poly. q at i for all i
        # shares = {}
        # for i in range(0, n):
        #     shares[pol_S[i]] = (i + 1, y[i])

        return y

    # shares is a dictionary
    def recoverCoefficients(self, list):
        coeff = []
        for i in list:
            result = 1
            for j in list:
                if not (i == j):
                    # lagrange basis poly
                    result *= (0 - j) / (i - j)
            coeff.append(result)
        return coeff

    def H(self, X):
        return group.hash(X, G1)

    def setup(self, attributes):
        alpha, beta, g = group.random(ZR), group.random(ZR), group.random(G1)
        g_alpha = g ** alpha
        g_beta = g ** beta

        # attribute keys generation
        self.attributeSecrets = {}
        self.attribute = {}
        for attr in attributes:
            si = group.random(ZR)
            self.attributeSecrets[attr] = si
            self.attribute[attr] = g ** si

        PP = {'g': g, 'g_beta': g_beta, 'g_alpha': g_alpha }
        msk = {'alpha': alpha, 'beta': beta}

        return (PP, msk)

    def register(self, id, sigma):
        # generate a user identifier
        w, theta = group.random(ZR), group.random(ZR)
        self.id[id] = [w, theta] # theta is symmetric key
        rk = []

        # calculate the register key
        for attr in sigma:
            rk.append(self.attribute[attr] ** w)

        return rk, theta

    def ekgen(self, PP, msk, pol_S):
        g = PP['g']; alpha = msk['alpha']

        # generate the Lagrange coefficients
        y = self.genShares(alpha, pol_S)
        l_0 = self.recoverCoefficients([group.init(ZR, i) for i in range(1, len(pol_S) + 1)])

        # calculate the encryption key ek_S, random points are (1, _), (2, _), (3, _), (4, _),...
        ek_S = []
        for i, attr in enumerate(pol_S):
            ek_S.append(g ** (l_0[i] * y[i+1]/self.attributeSecrets[attr])) # l_0 list begin from 0, y[0] should be the secret

        return ek_S

    def dkgen(self, PP, msk, pol_R):
        g = PP['g']; beta = msk['beta']

        # generate the Lagrange coefficients
        y = self.genShares(beta, pol_R)
        l_0 = self.recoverCoefficients([group.init(ZR, i) for i in range(1, len(pol_R) + 1)])

        # calculate the encryption key dk_R
        dk_R = []
        for i, attr in enumerate(pol_R):
            dk_R.append(g ** (l_0[i] * y[i+1]/self.attributeSecrets[attr]))

        return dk_R

    def pkgen(self, PP, rk, dk_R, id):
        ppk1=[]; ppk2=[]
        x = group.random(ZR)
        for i in range(len(dk_R)):
            ppk1.append(dk_R[i] ** x)
        for i in range(len(rk)):
            ppk2.append(rk[i] ** x)
        ppk3 = PP['g'] ** x

        ppk = {'ppk1': ppk1, 'ppk2': ppk2, 'ppk3': ppk3, 'id': id}
        return ppk, x

    def enc(self, PP, rk, ek_S, theta, m, id):
        g = PP['g']; g_beta = PP['g_beta']; g_alpha = PP['g_alpha']
        r = [group.random(ZR) for i in range(5)]
        R = [g**r[i] for i in range(5)]
        H_r1r3 = self.H(pair(R[1], R[3]))
        H_r2r4 = self.H(pair(R[2], R[4]))

        # calculate the ciphertext
        c0 = bytes([ a ^ b ^ c for (a,b,c) in zip(m, group.serialize(H_r1r3), group.serialize(H_r2r4))])
        symcrypt = SymmetricCryptoAbstraction(extractor(theta))
        c0 = symcrypt.encrypt(c0)
        c1 = []; c2=[]

        for i in range(len(rk)):
            c1.append(rk[i] ** r[1])
        for i in range(len(ek_S)):
            c2.append(ek_S[i] ** r[2])
        c3 = pair(R[1],R[3]) * pair(R[1],g_beta)
        c4 = pair(R[2],R[4]) * pair(R[2],g_alpha)
        c5 = (g_alpha ** r[2]) / (g_beta ** r[1])
        c = {'c0': c0, 'c1': c1, 'c2': c2, 'c3': c3, 'c4': c4, 'c5': c5, 'id': id}

        return c

    def match(self, c, ppk):
        c0 = c['c0']; c1 = c['c1']; c2 = c['c2']; c3 = c['c3']; c4 = c['c4']; c5 = c['c5'];
        ppk1 = ppk['ppk1']; ppk2 = ppk['ppk2']; ppk3 = ppk['ppk3']
        c1_prime = []; c2_prime = []
        ws = self.id[c['id']][0]; wr = self.id[ppk['id']][0]

        if len(ppk2)<len(c2) or len(ppk1)>len(c1):
            return False

        # remove the identifiers
        for i in range(len(c1)):
            c1_prime.append(c1[i] ** (1/ws))
        for i in range(len(c2)):
            c2_prime.append(c2[i] ** (1/wr))

        for item1 in combinations(ppk2,len(c2_prime)):
            verf_up = 1;
            # compute verf_up
            for i in range(len(item1)):
                verf_up *= pair(c2_prime[i], item1[i])
            for item2 in combinations(c1_prime,len(ppk1)):
                verf_down = 1
                # compute verf_down
                for j in range(len(item2)):
                    verf_down *= pair(item2[j], ppk1[j])

                verf = verf_up / verf_down
                if verf == pair(ppk3, c5):
                    theta = self.id[c['id']][1]
                    symcrypt = SymmetricCryptoAbstraction(extractor(theta))
                    c0_prime = symcrypt.decrypt(c0)
                    v1 = verf_up
                    v2 = verf_down
                    c_prime = {'c0_prime': c0_prime, 'v1': v1, 'v2': v2, 'c3': c3, 'c4': c4}
                    return c_prime
        return False

    def dec(self,c_prime,psk):
        c0_prime = c_prime['c0_prime'];v1 = c_prime['v1'];v2 = c_prime['v2'];c3 = c_prime['c3'];c4 = c_prime['c4']
        h1 = self.H(c4/(v1 ** (1/psk)))
        h2 = self.H(c3/(v2 ** (1/psk)))

        # recover the message
        m = bytes([ a ^ b ^ c for (a,b,c) in zip(c0_prime, group.serialize(h1), group.serialize(h2))])

        return m

    def rev(self, id=None, att_j=None, rk=None, ek_S=None, dk_R=None, rk_sigma=None, rk_rho=None, ppk=None, c=None):
        if id is not None:
            w_new = group.random(ZR); w_old = self.id[id][0]
            for i in rk:
                rk[i] = rk[i] ** (w_new / w_old)
            return rk

        if att_j is not None:
            si_new = group.random(ZR); si_old = self.attributeSecrets[att_j]
            UK = si_new / si_old
            self.attributeSecrets[att_j] = si_new
            self.attribute[att_j] = self.attribute[att_j] ** UK

            # update keys
            for i in ek_S:
                ek_S[i] = ek_S[i] ** (1/UK)
            for i in dk_R:
                dk_R[i] = dk_R[i] ** (1/UK)
            for i in rk_sigma:
                rk_sigma[i] = rk_sigma[i] ** UK
            for i in rk_rho:
                rk_rho[i] = rk_rho[i] ** UK
            ppk1 = ppk['ppk1']; ppk2 = ppk['ppk2']
            for i in range(len(ppk1)):
                ppk1[i] = ppk1[i] ** (1/UK)
            for i in range(len(ppk2)):
                ppk2[i] = ppk2[i] ** (1/UK)
            c1 = c['c1']; c2 = c['c2']
            for i in range(len(c1)):
                c1[i] = c1[i] ** (1/UK)
            for i in range(len(c2)):
                c2[i] = c2[i] ** UK

            return (ek_S, dk_R, rk_sigma, rk_rho, ppk, c)

def get_size(obj, seen=None):
    """递归计算对象的大小"""
    from numbers import Number
    from collections import abc
    from sys import getsizeof

    if seen is None:
        seen = set()

    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)

    size = getsizeof(obj)

    if isinstance(obj, (str, bytes, Number, range, bytearray)):
        pass
    elif isinstance(obj, (tuple, list, set, frozenset)):
        size += sum(get_size(i, seen) for i in obj)
    elif isinstance(obj, abc.Mapping):
        size += sum(get_size(k, seen) + get_size(v, seen) for k, v in obj.items())
    elif hasattr(obj, '__dict__'):
        size += get_size(obj.__dict__, seen)

    return size

def measure_time(func, *args, **kwargs):
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    return result, end_time - start_time

def measure_size(obj):
    return get_size(obj)

if __name__ == '__main__':
    group = PairingGroup('SS512')
    ME = CRO_MABE(group)
    m = b"hello world!!!!!"
    attributes = ["ATT" + str(i) for i in range(15)]

    # Setup
    (PP, msk), setup_time = measure_time(ME.setup, attributes)
    print(f"Setup Time: {setup_time:.6f} seconds")
    print(f"Public Parameter Size: {measure_size(PP)} bytes")
    print(f"Master Secret Key Size: {measure_size(msk)} bytes")

    sender_att = ["ATT" + str(i) for i in range(15)]
    sender_id = 'id555'
    receiver_att = ["ATT" + str(i) for i in range(15)]
    receiver_id = 'id666'

    # Register
    (rk_sigma, theta), register_sender_time = measure_time(ME.register, sender_id, sender_att)
    print(f"Register Sender Time: {register_sender_time:.6f} seconds")
    print(f"Sender's Private Key Size: {measure_size(rk_sigma)} bytes")

    (rk_rho, _), register_receiver_time = measure_time(ME.register, receiver_id, receiver_att)
    print(f"Register Receiver Time: {register_receiver_time:.6f} seconds")
    print(f"Receiver's Private Key Size: {measure_size(rk_rho)} bytes")

    pol_S = ["ATT" + str(i) for i in range(15)]
    pol_R = ["ATT" + str(i) for i in range(15)]

    # Key Generation
    ek_S, ekgen_time = measure_time(ME.ekgen, PP, msk, pol_S)
    print(f"Encryption Key Generation Time: {ekgen_time:.6f} seconds")
    print(f"Encryption Key Size: {measure_size(ek_S)} bytes")

    dk_R, dkgen_time = measure_time(ME.dkgen, PP, msk, pol_R)
    print(f"Decryption Key Generation Time: {dkgen_time:.6f} seconds")
    print(f"Decryption Key Size: {measure_size(dk_R)} bytes")

    # Proxy Key Generation
    (ppk, psk), pkgen_time = measure_time(ME.pkgen, PP, rk_rho, dk_R, receiver_id)
    print(f"Proxy Key Generation Time: {pkgen_time:.6f} seconds")
    print(f"Proxy Public Key Size: {measure_size(ppk)} bytes")
    print(f"Proxy Secret Key Size: {measure_size(psk)} bytes")

    # Encryption
    c, enc_time = measure_time(ME.enc, PP, rk_sigma, ek_S, theta, m, sender_id)
    print(f"Encryption Time: {enc_time:.6f} seconds")
    print(f"Ciphertext Size: {measure_size(c)} bytes")

    # Matching
    c_prime, match_time = measure_time(ME.match, c, ppk)
    print(f"Matching Time: {match_time:.6f} seconds")
    print(f"Matched Ciphertext Size: {measure_size(c_prime)} bytes")

    # Decryption
    m_dec, dec_time = measure_time(ME.dec, c_prime, psk)
    print(f"Decryption Time: {dec_time:.6f} seconds")

    print(f"Decrypted message: {m_dec}")
    print(f"Original message: {m}")
    print(f"Decryption {'succeeded' if m_dec == m else 'failed'}")

    # Communication Complexity
    print(f"\nCommunication Complexity:")
    print(f"KA and User: {measure_size(PP) + measure_size(msk) + measure_size(ek_S) + measure_size(dk_R)} bytes")
    print(f"Edge Server and Sender: {measure_size(c)} bytes")
    print(f"Edge Server and Receiver: {measure_size(c_prime)} bytes")


