import time
import sys
CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'


def progressBar(prev, curr):
    bar = "█"
    pB = "█"

    print("\r", end="")
    if prev != 0:
        for i in range(prev + 1):
            pB = pB + bar
            
    for i in range(prev, curr + 1):
        time.sleep(0.02)
        if i != curr:
            sys.stdout.write(CURSOR_UP_ONE)
            sys.stdout.write(ERASE_LINE)
            print("|{1}|{0}%".format(i+1, pB))
        pB = pB + bar
