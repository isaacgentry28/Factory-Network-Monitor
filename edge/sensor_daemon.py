"""
Socket 1 sender (UDP => HMI:5005)

Samples temperature, humidity, and pressure ocer per second, 
and sends each reading as one JSON datagream, in the exact format in Docs/protocol.md:

 {"node": "sensehat", "seq": 42, "ts": 1731250000.123,
   "temp_c": 23.4, "humidity": 41.2, "pressure_hpa": 1012.8}

Run (repo root):  python3 -m edge.sensor_daemon
Test without the HMI:  nc -ul 5005  on another machine, and HMI_IP=<that IP>
"""
import json
import socket
import time

from common import config
from edge import edgelib
from edge.edgelib import log

C = "sensor"
HMI_IP = edgelib.HMI_IP
TELEMETRY_PORT = config.get_int("TELEMETRY_PORT")
SAMPLE_EVERY_S = 1.0
TEMP_OFFSET_C = config.get_float("TEMP_OFFSET_C", 17.5)

def read_sensors(sense, temp_offset_c):
    """Return plain floats (never strings/bools bc HMI rejects those)."""
    raw_c = float(sense.get_temperature())
    return {
        "temp_c": round(raw_c - temp_offset_c, 2),   # corrected to room temperature
        "temp_raw_c": round(raw_c, 2),               # extra field, for calibration
        "humidity": round(float(sense.get_humidity()), 2),
        "pressure_hpa": round(float(sense.get_pressure()), 2),
    }


def main():
    sense = edgelib.get_sensehat(C)
    # The fake Sense HAT already returns room temperature, so don't correct it
    offset = 0.0 if isinstance(sense, edgelib.FakeSenseHat) else TEMP_OFFSET_C
    log(C, f"temperature correction: -{offset:.1f} C")

    #The pressure sensor often returns 0 on its very first read; probably need to throw one away.
    read_sensors(sense, offset)
    time.sleep(0.2)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #client: OS picks the port
    seq = 0
    next_sample = time.time()
    log(C, f"sending telemetry to {HMI_IP}:{TELEMETRY_PORT} at 1 Hz")
    
    try:
        while True:
            seq +=1 
            reading = {"node": edgelib.NODE, "seq": seq, "ts": time.time(), **read_sensors(sense, offset)}
            try:
                sock.sendto(json.dumps(reading).encode("utf-8"), (HMI_IP, TELEMETRY_PORT))
            except OSError as e:
                #ie. network not up yet after boot. UDP has not connection, so just try next second.
                log(C, f"send failed({e}); will retry")
            if seq % 30 == 1:
                log(C, f"#{seq} {reading['temp_c']} C {reading['humidity']} % {reading['pressure_hpa']} hPa")
                
            #schedule from the plan, not from "now", so the 1 Hz rate never drifts.
            next_sample += SAMPLE_EVERY_S
            delay = next_sample - time.time()
            if delay > 0:
                time.sleep(delay)
            else:
                next_sample = time.time() # we fell behind; resync
    except KeyboardInterrupt:
        log(C, f"stopped after {seq} readings")
    finally:
        sock.close()
        
if __name__ == "__main__":
    main()
