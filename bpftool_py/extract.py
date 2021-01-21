import subprocess
proc=subprocess.Popen(["sudo", "/usr/sbin/bpftool","map","dump","name","stats"], stdout=subprocess.PIPE)
output=proc.stdout.read()
output=output.decode("utf-8")
output=output.split("\n")
num=output[-2].split(" ")
num=int(num[1])
sing_drop_WL = 0
sing_pass_WL = 0
sing_drop_nonWL = 0
sing_pass_nonWL = 0
mult_drop_nonWL = 0
mult_pass_nonWL = 0
mult_pass_WL = 0
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
        valout = valout+b
    valout = int(valout, 16)
    if(key == 1):
        sing_drop_WL = valout
    elif(key == 2):
        sing_pass_WL = valout
    elif(key == 3):
        sing_drop_nonWL = valout
    elif(key == 4):
        sing_pass_nonWL = valout
    elif (key == 5):
        mult_drop_nonWL = valout
    elif (key == 6):
        mult_pass_nonWL = valout
    elif (key == 7):
        mult_pass_WL = valout

print("sing_pass_nonWL:", sing_pass_nonWL)
print("sing_drop_nonWL:", sing_drop_nonWL)
print("sing_pass_WL:", sing_pass_WL)
print("sing_drop_WL:", sing_drop_WL)
print("mult_pass_nonWL:", mult_pass_nonWL)
print("mult_drop_nonWL:", mult_drop_nonWL)
print("mult_pass_WL:", mult_pass_WL)
