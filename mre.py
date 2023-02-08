#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
import re
import json

VERSION = 0.9

def existing_pid(pid: int) -> (int | argparse.ArgumentTypeError):
    try:
        pid = int(pid)
    except:
        raise argparse.ArgumentTypeError(f"Invalid PID!")    
    if Path(f"/proc/{pid}").exists():
        return pid
    raise argparse.ArgumentTypeError(f"PID {pid} is not running!")


def get_memory_info(pid: int) -> dict:
    with open(f"/proc/{pid}/maps", "r") as mf:
        maps = mf.read()
    regex = r'^(?P<saddr>[a-f0-9]+)-(?P<eaddr>[a-f0-9]+)\s+(?P<perms>[rxwp-]+).*(\[heap\])$'
    m = re.search(regex, maps, re.MULTILINE)
    heap = m.groupdict()
    for key in ["saddr", "eaddr"]:
        heap[key] = int(heap[key], 16)
    return heap


def get_environ(pid: int) -> dict:
    with open(f"/proc/{pid}/environ", "rb") as ef:
        benv = ef.read().split(b'\0')
    env = {}
    for e in benv:
        if e:
            key, val = e.decode().split("=")
            env[key] = val
    return env


def get_memory(pid: int, saddr: int, eaddr: int) -> bytes:
    length = eaddr - saddr
    with open(f"/proc/{pid}/mem", "rb") as mf:
        mf.seek(saddr)
        return mf.read(length)


def get_possible_variables(mem: bytes) -> dict:
    regex = rb'\0(\w+)=(.+?)\0'
    matches = re.findall(regex, mem)
    variables = []
    for m in matches:
        variables.append(m)
    return variables


def replace_in_memory(pid: int, saddr: int, mem: bytes, oldval: bytes, newval: bytes, force: bool):
    with open(f"/proc/{pid}/mem", "r+b") as mf:
        matches = re.finditer(oldval, mem)
        for m in matches:
            try:
                mf.seek(saddr+m.start(0))
                ol = m.end(0) - m.start(0)
                cv = mf.read(ol)
                mf.seek(saddr+m.start(0))
                nl = len(newval)
                pad = b'\0'
                if ol >= nl:
                    pad += b'\0' * (ol - nl)
                elif not force:
                    print(
                        f"Skipping {saddr+m.start(0)}: new value is too long! ( --force? )")
                    print(f"Was: {cv} [{ol} bytes]")
                    print(f"New: {newval} [{nl} bytes]")
                    continue
                mf.write(newval + pad)
                mf.seek(saddr+m.start(0))
                print("FROM:", cv)
                nv = mf.read(ol + 1)
                if nv.endswith(b'\0\0\0'):
                    idx = len(nv)
                    while nv[idx - 1] == 0:
                        idx -= 1
                    diff = len(nv) - idx
                    nv = nv[0:idx]
                    nv += b'\0' + f'[*{diff}]'.encode()
                print("TO:", nv)
            except:
                pass


def main(pid: int, listenv: bool = False, environ: bool = False, dumpheap: bool = False, replace: list = None, rfilter: str = None, force: bool = False):
    if environ:
        jdata = get_environ(pid)
        print(json.dumps(jdata, indent=2))
    else:
        heap = get_memory_info(pid)
        if heap["perms"][0] == "r":  # heap is readable
            mem = get_memory(pid, heap["saddr"], heap["eaddr"])
            if listenv:
                vars = get_possible_variables(mem)
                for v in vars:
                    key = v[0]
                    val = v[1]
                    try:
                        print(f"{key.decode()}={val.decode()}")
                    except:
                        print(f"{key.decode()}={val}")
            elif dumpheap:
                if rfilter:
                    matches = re.finditer(rfilter.encode(), mem)
                    for m in matches:
                        print(hex(m.start()), m.group())
                else:
                    sys.stdout.buffer.write(mem)
            elif replace:
                if heap["perms"][1] != "w":  # heap is writable
                    raise Exception(f"Heap is unwritable! ({heap['perms']})")

                oldval, newval = replace
                oldval = oldval.encode()
                newval = newval.encode().decode('unicode_escape').encode()
                replace_in_memory(
                    pid, heap["saddr"], mem, oldval, newval, force)
        else:
            raise Exception(f"Unreadable heap! ({heap['perms']})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(epilog=f"MRE (Memory Retriever and Editor) v{VERSION} by ShotokanZH")
    parser.add_argument("PID", type=existing_pid)
    parser.add_argument(
        "-l", "--list", help="lists all the possible bash variables used by PID (even the unexported ones)", action='store_true')
    parser.add_argument(
        "-e", "--environ", help="lists all the (exported) environment variables", action='store_true')
    parser.add_argument(
        "-d", "--dumpheap", help="dumps heap memory to stdout", action='store_true')
    parser.add_argument(
        "-r", "--replace", help="searches the heap (using regex) for OLDVAL and replaces it with NEWVAL (NEWVAL needs to be shorter or the same length as the computed current value)", nargs=2, metavar=("OLDVAL", "NEWVAL"))
    parser.add_argument(
        "-f", "--filter", help="used with -d, dumps only what matches the regex", metavar=("REGF",), type=str)
    parser.add_argument(
        "-x", "--force", help="used with -r, forces replaces even in shorter strings (dangerous!)", action='store_true')
    args = parser.parse_args()

    if not (args.list or args.environ or args.dumpheap or args.replace):
        parser.error('No action requested!')
    main(args.PID, listenv=args.list, environ=args.environ, dumpheap=args.dumpheap,
         replace=args.replace, rfilter=args.filter, force=args.force)
