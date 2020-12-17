import os
import time

while (1):
    drop_gen1 = os.popen("sudo bpftool map lookup name stats key 01 00 00 00").read()
    pass_gen1 = os.popen("sudo bpftool map lookup name stats key 02 00 00 00").read()
    drop_gen2 = os.popen("sudo bpftool map lookup name stats key 03 00 00 00").read()
    pass_gen2 = os.popen("sudo bpftool map lookup name stats key 04 00 00 00").read()
    
    def print_res(inp):
        inp = inp.split("\n")
        if (inp[3] == "Not found"):
            return -1
        else:
            val = inp[2]
            val = val.split(":")
            val = val[1].split(" ")
            lval = len(val)-1
            out = ""
            flag = 0
            while (val[lval] != ''):
                if ((val[lval] == "00") & (flag == 0)):
                    pass
                else:
                    flag = 1
                    out += val[lval]
                lval -= 1
            return int(out,16)
    
    dg1 = print_res(drop_gen1)
    pg1 = print_res(pass_gen1)
    dg2 = print_res(drop_gen2)
    pg2 = print_res(pass_gen2)
    
    print("pass_gen1",pg1,"drop_gen1",dg1,"pass_gen2",pg2,"drop_gen2",dg2)
    time.sleep(2)
