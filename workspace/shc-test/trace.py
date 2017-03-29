#!/usr/bin/env python


import r2pipe as r2p


def main():
    r = r2p.open()
    with open("trace.log", "a") as t:
        i = r.cmdj("pdj 0x1 @ `dr?rip`")[0]
        while i['type'] != 'invalid':
            i = r.cmdj("pdj 0x1 @ `dr?rip`")[0]
            if i["type"] == "call":
                t.write("0x%x:  %s\n" % (i["offset"], i["opcode"]))
            r.cmd("ds")


if(__name__ == "__main__"):
    main()
