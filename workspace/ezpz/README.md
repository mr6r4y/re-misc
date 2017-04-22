# ezpz by Gynvael

This crackme is from Gynvael's https://www.youtube.com/watch?v=JExnV1-GNxk . The solution script can be
used either statically:

```bash
./ezpz_solution -f ezpz
```

or within *radare2* debug session:

```
r2 -d ./ezpz

[0x7fa8478c0cc0]> #!pipe ./ezpz_solution.py
```
