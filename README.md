# Rotorhazard Backpack Bridge
Rotorhazard backpack bridge. This simple tool is usefull to 
use a cheap ESP32 Dev Kit and connect it via network close 
to the pilots HDZero goggles.

![rh-backpack-bridge usage](https://github.com/clemix-fpv/rh-backpack-bridge/blob/main/images/rh_bridge.png?raw=true)


# Installation:

1) Install the [VRxC_ELRS](https://github.com/i-am-grub/VRxC_ELRS) plugin. 

2) Install the script via pip. 
    ```
    git clone git@github.com:clemix-fpv/rh-backpack-bridge.git 
    cd rh-backpack-bridge
    python3 -m venv .venv
    . .venv/bin/activate
    pip install .
    ```

# Usage:

1) Start the script
    ```
    rh-backpack-bridge --device /dev/ttyUSB0 --port 8080
    ```

2) Configure the plugin. Select `Backpack Connection Type = Socket` and enter the 
   IP-Address in `ELRS Netpack Address` of the device where you run 
   the `rh-backpack-bridge` script. 
   ![rh-backpack-bridge setup](https://github.com/clemix-fpv/rh-backpack-bridge/blob/main/images/rh_setup.png?raw=true)




