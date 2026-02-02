from Crypto.Util.number import getPrime, bytes_to_long

bflag = b"CSL24{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 3

flag = bytes_to_long(bflag)

print("n = {}\ne = {}\nc = {}".format(n, e, pow(flag, e, n)))
