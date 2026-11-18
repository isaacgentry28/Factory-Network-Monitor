"""
led_status.py - the only process that draws on the Sense HAT LED matrix.

Checks the state files 5 times per second and shows the highest-priority state:

  1. RED    any host is quarantined           (quarantine.json, FR-2.6)
  2. AMBER  a tamper alert waiting for a joystick ack (alert.json, FR-3.4)
  3. a command pattern from the HMI           (led_pattern.json, S2 led_pattern)
  4. GREEN  normal operation

Red always wins, so an led_pattern command can't hide an active quarantine.

Run (repo root):  python3 -m edge.led_status
"""
import time

from edge import edgelib
from edge.edgelib import log

C = "led"
POLL_S = 0.2

OFF = (0, 0, 0)
GREEN = (0, 150, 0)
AMBER = (255, 110, 0)
RED = (200, 0, 0)


def solid(color):
    return [color] * 64


def border(color, inner=OFF):
    """Outline only - easier on the eyes than a full bright matrix."""
    pixels = []
    for y in range(8):
        for x in range(8):
            edge = x in (0, 7) or y in (0, 7)
            pixels.append(color if edge else inner)
    return pixels


def checkerboard(a, b):
    return [a if (x + y) % 2 == 0 else b for y in range(8) for x in range(8)]


def rainbow():
    cols = [(255, 0, 0), (255, 127, 0), (255, 255, 0), (0, 255, 0),
            (0, 0, 255), (75, 0, 130), (148, 0, 211), (255, 255, 255)]
    return [cols[x] for y in range(8) for x in range(8)]


# Patterns the HMI may request with {"command": "led_pattern", "pattern": ...}.
# command_service.py checks names against this dict.
PATTERNS = {
    "test": rainbow,
    "checker": lambda: checkerboard((0, 0, 255), (255, 255, 255)),
    "blue": lambda: solid((0, 0, 150)),
    "white": lambda: solid((120, 120, 120)),
}

STATES = {
    "quarantine": lambda: solid(RED),
    "alert": lambda: border(AMBER, inner=(60, 25, 0)),
    "normal": lambda: border(GREEN),
}


def current_state():
    """Return (name, pixels) for what should be on the matrix right now."""
    if edgelib.quarantine_count() > 0:
        return "quarantine", STATES["quarantine"]()
    alert = edgelib.read_state("alert.json")
    if alert and alert.get("active"):
        return f"alert ({alert.get('reason')})", STATES["alert"]()
    pat = edgelib.read_state("led_pattern.json")
    if pat and pat.get("pattern") in PATTERNS:
        return f"pattern {pat['pattern']}", PATTERNS[pat["pattern"]]()
    return "normal", STATES["normal"]()


def main():
    sense = edgelib.get_sensehat(C)
    shown = None
    log(C, "LED status driver running")
    try:
        while True:
            name, pixels = current_state()
            if name != shown:                 # only redraw when something changed
                sense.set_pixels(pixels)
                log(C, f"LED -> {name}")
                shown = name
            time.sleep(POLL_S)
    except KeyboardInterrupt:
        pass
    finally:
        sense.clear()
        log(C, "stopped, matrix cleared")


if __name__ == "__main__":
    main()