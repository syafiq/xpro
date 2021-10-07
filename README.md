This is the implementation work for X-Pro paper, presented at Nordsec 2021. 

There are three main components in the implementation, i.e.:
1. Proxy
2. Database
3. IoT 

# Proxy
The proxy implementation is inside /src. To attach the XPRO logic to the interface, there is a script to load and unload the BPF program (called load/reload.sh). First, compile the source code by calling `make`, and then you can attach the program `xpro_kern` to your designated interface. Please make sure that the interface name is the same as in your machine (it is defined in the load script). 

# Database
No fancy stuff, it is just a single instance redis db. 

# IoT
The implementation for the IoT part is divided into two part:
## Separate Main and Net MCU (Connected through UART)
Under `/esp` and `/coap_client`.
## Integrated Main and Net MCU
Under `/esp_code`
