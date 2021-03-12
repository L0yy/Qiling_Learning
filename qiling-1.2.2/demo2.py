from qiling import *
    
        
ql = Qiling(["/home/kali/Documents/Qiling_Learning/qiling-1.2.2/examples/rootfs/x8664_windows/bin/x8664_hello.exe"], 
"/home/kali/Documents/Qiling_Learning/qiling-1.2.2/examples/windwosDlls/x8664_windows",
output="default")
ql.run()