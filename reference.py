import threading
import time

class ref():
    def __init__(self, initVal=None):
        self.var=initVal

def myFun(test):
    time.sleep(5)
    test.var=5

test = ref()

threading.Thread(target=myFun, args=(test,)).start()

while True:
    print(test.var)
    time.sleep(1)
