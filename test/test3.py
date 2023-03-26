import paramiko
import io

private_key_file = io.StringIO()

def myfakefile(keystring):
    myfakefile.readlines=lambda: keystring.split("\n")
    return myfakefile

key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwm45dc+JfA3T8JZl0EDy8KsW2tfkMX38ACR1mwyOHGytVUHa
TKCP5Acq8iX9K8aZSUt7f63xuy+cndQx/9MEMH8UuQM2Mf6ui/pLgAnw6FUAHr3W
zAtahGADGqSei4ViuMJJ5P9Yfy6pB3XKtw4g0fClLHi12zfl3roqAt8b0F1h6D5c
yW0spOV9cX0i1IVdv50VFHRlNDEUTqE4vuxVTOLb4wECkI6DTuGr30LcnmkWvg5J
BmlpP06gXIbU3YaBH4dHunUloCmbEVcz9ufnyiaBZxFYudB5v+SQAtEbmAXcN2HU
1LnT2qhkstD4QEpQIloDPsFmgevCneAdVPLhzwIDAQABAoIBAC35tHqoNaFw/6HP
XontIcVJH6FmFZ6iZNl/xZOBV4VfKWmUpdMi0IOiMkSKOSCF2K9dOvnJHvUdYBJu
H9iXhFEXa8YH/WO7DnkpGXtQXngByYJ7b3RWZvQQZAuDy73AL8TypFiTDNEeLngG
IYZBv/8EwXoPnSkWQbP2H4MIUOJnGNkIYtJkZ7L1ui3xUaT467eY10mGlGoz8Vf+
xsolKWIe8+Cr6vO7UEVFq3lN0M62/9W7cIgEWcPurDzAgi7nQt2QfMPysvf3+/Bx
lDcOAvqiKg79xfLW74xGjDdpdEwJGyEP6jMC496dOFxt06t+jU+Z+YHz6twc9qkm
ObJ56NECgYEA0y3fCfUgl70EL9oVqx0jYK2ngLetsPQVPo+O1p7ngEcCfpbzi3Fc
EY+wJZM/K+gkFf9FeYLLfjgY3Qb1L1tzQieTXiAeOFFnkDsh5XY9IzSYKRkKQ0Q+
W1hrS3zz6knVDPk1e8OIpYzv5VyjFT3BB3SSqaDkOmvqEIlJWPSJGscCgYEA67JX
EPhsVI6WCerNUOyVCdS+9/OM3vTbd3SAZ9NWQ3/h80hBrDAPE498k3rTTadBtNwi
fVshRE95jje0yMDoSHQbMKUznCuSlXW6D8SsYuDVDYCx+iz8nMpB+CecNdtPAQ/3
y63xST0AbEd1GZWe5Pcz0GzC8U9INC9NdPTlOLkCgYBASOByeYo4ZrOVlX+vHSmd
zn8E8eUPzt2As9a5gpnaNMOPoYf11MZAGkt2xMIgLYR+pbySZrxnadA3yFxu1Bnb
84wqxQAuCKnMABQrc7jctK/1Isg6/dU1nU7cJediVKNkVaBwUm+QZbzJR0/lsWzH
Rjc3J+ER37Pa4M/RIm9yFQKBgQCxlDd3CMSN3LP8mtTAUM9ljc2oAO61GOS1lqgc
EaVfy90QL/OS6M6jHStt7k9/pTGjM2wk6GEjF4Hs/dmOm5Em7ZuCxiUhV87kHsPl
l3eOM/kxaDIv3G8jLlwPvMA775URptc6tT4iwPwtmJUIhqsltX5rXVZu+x3ae30v
TkfZuQKBgQCu0Q6eKXuIrLwZsOcHFZ46GHrQnZcBQWbWCUSVuy7Gd9kslfb1F2FA
6O61JuEYOIJI+f80/6NuoPglxljQVwSed0aHstnDa9acd3OZ9KKhpeJzPVTCCd/P
GS8i9iadnOnUwhh/pAfPWBcUL9KZ7D3LFP2e4tx3ti9MjA4E03jaiQ==
-----END RSA PRIVATE KEY-----
"""

edKey = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBnDG2D3dr5XUzLT56mCDa6M7txcKx92/CB+4SLmoStHQAAAJjb3Du229w7
tgAAAAtzc2gtZWQyNTUxOQAAACBnDG2D3dr5XUzLT56mCDa6M7txcKx92/CB+4SLmoStHQ
AAAEACjHW0K099Xv3tvNcEm7inac+B9w7zuUqkO2j3zJr5W2cMbYPd2vldTMtPnqYINroz
u3FwrH3b8IH7hIuahK0dAAAADnRlc3RAdGVzdC50ZXN0AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
"""

private_key_file.write(key)
private_key_file.seek(0)

print(key)
private_key = paramiko.RSAKey.from_private_key(private_key_file)
#host_key = paramiko.RSAKey(file_obj=myfakefile(key))

#mykey = paramiko.RSAKey.from_private_key(myfakefile(key))

#if mykey == private_key:
#    print("equal")

mykey = paramiko.ed25519key.Ed25519Key(file_obj=myfakefile(edKey))

if mykey == private_key:
    print("equal")
    
#print(mykey)

client_key = b"AAAAB3NzaC1yc2EAAAADAQABAAACAQDBgsFOvSmvmBiBbfbhtWp/ei4OhY2f+984kVucKkjGBFzebO+xriYGnhT++yfrYfL1s6pIFhg5EnOoBXl8cLAHL0l5WSsukc4jSGKtWZU3EjsLebuL83GKBvuLSacv4caiuMtIM9FKKA2HnKkPi3MVRZSNYuxqPjOkxrQpnGCkqwW8LAHUNTYnDHMFLXY/NAgEYVCwdg+bQga2xKhNUqGZZoMwr5200UWQZgpYgUuQ3fFTsFf4ReOimN7WqbXNKJ7e/8t3p+6pcA8YDLWt9pSXCZEq/Q5NAow0/dsY/BHXHcetHafJlDVi8iMtfZ+qAIBuJoUL642tRRQAfp/26ujtXvnw7Ol8CSkTMdx69sMkHuBwx6Hn3rBQc4+13luwh9Bry/quM06pV2Z94DSTG53Bg1JQugcV81sjrlAJB3y2sNeaLfC2sQAp1YYa5XPB/vi0/WBpgRe8FnDCS5BxO5mJLkc5/LcyenUpYIgHYVwsQiO8OBBEQrwNXsGsDky985gGa4zCEmAZP5L23sX7voCeINvDHpKmJ2gkqxxi2f3AT0N6QToo9ipZHwifDmUdGnBIEtWCBGqDzkyT29sIM+QNYXpWNm43pz+mwN/bb8uWKDoE9dKmDRc6EwYS5XUPc1d/WZDPviRXLQ4fRnWQWmHjCyUoRaaqsUzeENPHu65IxQ=="

#pub_key_file = io.StringIO()
#pub_key_file.write(client_key)
#pub_key_file.seek(0)
#from paramiko.py3compat import b, u, decodebytes
import base64
pub_key = paramiko.RSAKey(data=base64.decodebytes(client_key))

print(pub_key.get_base64())

#good_pub_key = paramiko.RSAKey(data=decodebytes(client_key.encode()))