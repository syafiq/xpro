import time
import pycom
from machine import UART
from machine import Timer

pycom.heartbeat(False)
pycom.rgbled(0x0A0A08) # white
chrono = Timer.Chrono()

uart = UART(1, 115200)
uart.init(115200, bits=8, parity=None, stop=1)
while True:
    chrono.start()
    lap_1 = chrono.read_ms()
    uart.write("4500002500020000ef1117cb53fbaa91ac1f094fe6c3163300115ef540012d01b474696d65")
    while True:
        u=uart.read(50)
        if u:
            lap_2 = chrono.read_ms()
            print("td %f ms" % (lap_2-lap_1))
            print(u)
            break
    chrono.stop()
    time.sleep(5)
