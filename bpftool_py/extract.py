import subprocess
proc=subprocess.Popen(["sudo", "/usr/sbin/bpftool","map","dump","name","stats"], stdout=subprocess.PIPE)
output=proc.stdout.read()
output=output.decode("utf-8")
output=output.split("\n")
num=output[-2].split(" ")
num=int(num[1])
for a in range(num):
    valout = ""
    key=output[3*a+1]
    key=key.split(" ")
    key=int(key[0])
    val=output[3*a+2]
    val=val.split(":")
    val=val[1]
    val=val.split(" ")
    for b in reversed(val):
        if (b != '00'):
            valout = valout+b
    valout = int(valout, 16)
    if (key == 5):
        #print("drop_nonWL:", valout)
        drop_nonWL = valout
    elif (key == 6):
        #print("pass_nonWL:", valout)
        pass_nonWL = valout
    elif (key == 7):
        #print("pass_WL:", valout)
        pass_WL = valout

print("pass_nonWL:", pass_nonWL)
print("drop_nonWL:", drop_nonWL)
print("pass_WL:", pass_WL)
