class TestClass():
    def __init__(self, fun=None):
        if fun == None:
            self.fun = self.hallo
        else:
            self.fun=fun
    def hallo(self):
        print('testerr')
    def run(self):
        self.fun()

def otherFun():
    print('hi')

obj = TestClass(otherFun)
obj.run()