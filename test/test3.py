import paramiko
import io

private_key_file = io.StringIO()

def myfakefile(keystring):
    myfakefile.readlines=lambda: keystring.split("\n")
    return myfakefile

key = """***REMOVED: example key, purged from git history***
"""

edKey = """***REMOVED: example key, purged from git history***
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