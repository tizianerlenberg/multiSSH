class MsgType():
    Acknowledge  = b'\x00'
    Alive        = b'\x01'
    Byte         = b'\x02'
    Message_01   = b'\x03'
    Message_05   = b'\x04'
    Message_10   = b'\x05'

def encodeString(msg):
    msgLength = len(msg)
    if(msgLength <= 255):
        return MsgType.Message_01 + msgLength.to_bytes(1, 'big') + msg
    elif(msgLength <= 1099511627775):
        return MsgType.Message_05 + msgLength.to_bytes(5, 'big') + msg
    elif(msgLength <= 1208925819614629174706175):
        return MsgType.Message_10 + msgLength.to_bytes(10, 'big') + msg
    else:
        print('error')

def decodeString(msg):
    msgType = msg[0:1]
    msg = msg[1:]

    match msgType:
        case MsgType.Acknowledge:
            return ('Acknowledge')
        case MsgType.Alive:
            return ('Alive')
        case MsgType.Byte:
            return (msg[0:1])
        case MsgType.Message_01:
            codedLength = msg[0:1]
            msgLength = int.from_bytes(codedLength, 'big')
            return (msg[1:msgLength+1])
        case MsgType.Message_05:
            codedLength = msg[0:5]
            msgLength = int.from_bytes(codedLength, 'big')
            return (msg[5:msgLength+6])
        case MsgType.Message_10:
            codedLength = msg[0:10]
            msgLength = int.from_bytes(codedLength, 'big')
            return (msg[10:msgLength+11])

def main():
    #msg = MsgType.Byte + b'halloHallo'
    #matcher(msg)
    msg = encodeString(b"hallo")
    print(decodeString(msg))

if __name__ == '__main__':
    main()
