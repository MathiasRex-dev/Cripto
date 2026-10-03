#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: Matyi 

Replace this with a description of the program.
"""
import utils
import random
import math 

# Caesar Cipher

def encrypt_caesar(plaintext):
    """Encrypt plaintext using a Caesar cipher.

    Add more implementation details here.
    """
    ciphertext = ""

    for c in plaintext:
        if c.isalpha():
            if c.islower():
                new_chr = chr((ord(c) - ord('a') + 4) % 26 + ord('a'))
                ciphertext += new_chr
            else:
                new_chr = chr((ord(c) - ord('A') + 4) % 26 + ord('A'))
                ciphertext += new_chr
        else:
            ciphertext += c
    return ciphertext

def decrypt_caesar(ciphertext):
    """Decrypt a ciphertext using a Caesar cipher.

    Add more implementation details here.
    """
    plaintext = ""

    for c in ciphertext:
        if c.isalpha():
            if c.islower():
                plaintext += chr((ord(c) - ord('a') - 4) % 26 + ord('a'))
            else:
                plaintext += chr((ord(c) - ord('A') - 4) % 26 + ord('A'))
        else:
            plaintext += c

    return plaintext

# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    """Encrypt plaintext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    ciphertext = ""
    key_index = 0

    for c in plaintext:
        if c.isalpha():
            if c.islower():
                key_char = keyword[key_index % len(keyword)]
                shift = ord(key_char.lower()) - ord('a')
                ciphertext += chr((ord(c) - ord('a') + shift) % 26 + ord('a'))
                key_index += 1 
            else:
                key_char = keyword[key_index % len(keyword)]
                shift = ord(key_char.upper()) - ord('A')
                ciphertext += chr((ord(c) - ord('A') + shift) % 26 + ord('A'))
                key_index += 1
        else:
            ciphertext += c 

    return ciphertext


def decrypt_vigenere(ciphertext, keyword):
    """Decrypt ciphertext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """

    plaintext = ""
    key_index = 0

    for c in ciphertext:
        if c.isalpha():
            if c.islower():
                key_char = keyword[key_index % len(keyword)]
                shift = ord(key_char.lower()) - ord('a')
                plaintext += chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
                key_index += 1 
            else:
                key_char = keyword[key_index % len(keyword)]
                shift = ord(key_char.upper()) - ord('A')
                plaintext += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
                key_index += 1
        else:
            plaintext += c 

    return plaintext


# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    w = []
    w.append(random.randint(2, 10))
    total = w[0]
    for i in range(1,n):
        w.append(random.randint(total + 1, 2 * total))
        total += w[i]
    
    q = random.randint(total + 1, 2 * total)
    r = 2
    while True:
        r = random.randint(2, q - 1)
        if math.gcd(r, q) == 1:
            break 
    
    return (w, q, r)


def create_public_key(private_key: tuple):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    w, q, r = private_key
    n = len(w)
    beta = []
    for i in range(n):
        beta.append(r * w[i] % q)
    
    return beta

def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here

priv_key = generate_private_key()
pub_key = create_public_key(priv_key)
print(priv_key)
print(pub_key)
