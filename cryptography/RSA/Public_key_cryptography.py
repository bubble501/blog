def common_key(x, y):
    p = 13# Alice private key
    q = 53# Bob private key 
    
    alice_send_bob = (y ** p) % x# Alice public
    bob_send_alice = (y ** q) % x# Bob public
    
    alice_common = (bob_send_alice ** p) % x# Alice calculate
    bob_common   = (alice_send_bob ** q) % x# Bob calcu
    return alice_common == bob_common#(y ** (p*q))% x
# public number
x = 8420449# prime number
y = 553# integer
print(common_key(x, y))