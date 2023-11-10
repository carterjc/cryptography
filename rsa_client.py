"""
RSA test client
"""
from rsa import RSA

# basic demo

M = "IT'S ALL GREEK TO ME"

my_rsa = RSA()
my_rsa.generate_primes()
my_rsa.compute_e_d()
print(my_rsa)
cipher = my_rsa.encrypt(RSA.encode_message(M))
print(f"Ciphertext: {cipher}")
plain = my_rsa.decrypt(cipher)
print(f"Original message: {RSA.decode_message(plain)}")

# signature demo

M = "signature demo"

alice = RSA()
alice.generate_primes()
alice.compute_e_d()

bob = RSA()
bob.generate_primes()
bob.compute_e_d()

# bob's turn
# note that Bob only has access to his private key and alice's public key
# S = D_B(M)
bob_signature_bob = bob.decrypt(RSA.encode_message(M))
print("Bob creates his signature:", bob_signature_bob, "\n")
# C = E_A(S)
bob_signature_encrypted = alice.encrypt(bob_signature_bob)
print("Bob encrypts his signature with Alice's key:", bob_signature_encrypted, "\n")

# alice's turn
# S = D_A(C)
bob_signature_alice = alice.decrypt(bob_signature_encrypted)
print("Alice decrypts Bob's signature with her private key:", bob_signature_alice, "\n")
assert bob_signature_bob == bob_signature_alice
# M = E_B(S)
bob_message = bob.encrypt(bob_signature_alice)
print("Alice sees Bob's original message:", RSA.decode_message(bob_message))
