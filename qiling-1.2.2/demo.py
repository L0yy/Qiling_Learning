import unittest
import ntpath


class Test(unittest.TestCase):
    def test_callfunc(self):
        class A():
            def __init__(self):
                self.Name = "A Func"
                print(self.Name)

        class B():
            def __init__(self):
                self.Name = "B Func"

            def GetB(self):
                print(self.Name)

        class  C(A,B):
            def __init__(self):
                self.Name = "C Func"
                print("A Init")
        c = C()
        c.GetB()
        print("="*30)

    def test_ntpath_basename(self):
        path = r"C:\Users\Administrator\Downloads\qiling-1.2.2\qiling-1.2.2\ChangeLog\hello"
        print(ntpath.basename(path))

if __name__ == "__main__":
    unittest.main()