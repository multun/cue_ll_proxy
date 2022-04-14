# Cue LL Proxy

This program is a proxy for the iCUE low level access service.
It is known to work with iCUE `4.15.153`, but probably works pretty well with similar versions too.

# Usage
 
 - Install python 3.10+ (**make sure to tick the box to have python in the PATH**)
 - Open a terminal as administrator
 - Run the script

# Documentation

## Just run it

`python llproxy.py`

## Can I please only get the SMBus stuff?

`python llproxy.py -f SMBusWriteByte -f SMBusReadByte -f SMBusWriteByteCmdList`

## Can I get the logs of the actual service too?

`python llproxy.py --service-logs`

# How it works

This script does the following:
 - it stops CorsairLLAService
 - starts the process service as a subprocess of this script
 - finds the port the service runs on, and starts the proxy
 - opens the memory mapping CorsairLLAService uses to tell 
   iCUE where to connect to, and write the uri of the proxy
 - tries to cleanup and restart the service on exit

# Running this script broke iCUE

Well it shouldn't, but if it does you can either reboot, or follow these steps:

 - quit iCUE
 - `Win + R` -> `services.msc`
 - look for `CorsairLLAService`
 - restart it
 - open iCUE
