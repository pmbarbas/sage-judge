from __future__ import annotations
import argparse, json, sys
import os, stat
from pathlib import Path
from pathlib import PurePosixPath
from . import __version__
from .api import adjudicate, verify
from .errors import AdjudicationError
from .p01.canonical import canonical_bytes, loads_strict

def _safe_path(root,relative,*,output=False):
    if not isinstance(relative,str) or not relative or relative.startswith("/") or "\\" in relative or "\x00" in relative: raise ValueError("PATH_SYNTAX")
    parts=tuple(relative.split("/"))
    if str(PurePosixPath(relative))!=relative or any(p in {"",".",".."} or p.startswith(".") for p in parts): raise ValueError("PATH_NOT_CANONICAL")
    root_path=Path(root)
    if root_path.is_symlink(): raise ValueError("ROOT_SYMLINK")
    base=root_path.resolve(strict=True); path=base
    for part in parts:
        path=path/part
        if path.is_symlink(): raise ValueError("PATH_SYMLINK")
    if not path.resolve(strict=False).is_relative_to(base): raise ValueError("PATH_ESCAPE")
    if output:
        if not path.parent.is_dir() or path.exists(): raise ValueError("OUTPUT_MUST_BE_NEW_IN_EXISTING_DIRECTORY")
    else:
        fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1: raise ValueError("INPUT_NOT_SINGLE_LINK_REGULAR")
            raw=bytearray()
            while True:
                block=os.read(fd,1024*1024)
                if not block: break
                raw.extend(block)
                if len(raw)>2_000_000: raise ValueError("INPUT_BYTE_LIMIT")
        finally: os.close(fd)
        return bytes(raw)
    return path

def _read(root,relative):
    raw=_safe_path(root,relative)
    return loads_strict(raw)

def _write(root,relative,value):
    path=_safe_path(root,relative,output=True); raw=canonical_bytes(value)+b"\n"
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        view=memoryview(raw)
        while view:
            n=os.write(fd,view)
            if n<=0: raise OSError("SHORT_OUTPUT_WRITE")
            view=view[n:]
    finally: os.close(fd)

def main(argv=None):
    p=argparse.ArgumentParser(prog="sage-judge")
    p.add_argument("--version",action="version",version=f"sage-judge {__version__}")
    sub=p.add_subparsers(dest="command",required=True)
    a=sub.add_parser("adjudicate"); a.add_argument("--root",required=True); a.add_argument("--bundle",required=True); a.add_argument("--registry",required=True); a.add_argument("--policy",required=True); a.add_argument("--out",required=True)
    v=sub.add_parser("verify"); v.add_argument("--root",required=True); v.add_argument("--record",required=True); v.add_argument("--bundle",required=True); v.add_argument("--registry",required=True); v.add_argument("--policy",required=True)
    d=sub.add_parser("demo"); d.add_argument("--case",required=True)
    args=p.parse_args(argv)
    try:
        if args.command=="demo":
            demo_files={name: name+".json" for name in ("inspection_positive", "inspection_unknown", "inspection_conflict", "unsupported_dependency")}
            name=demo_files.get(args.case)
            if name is None: raise ValueError("DEMO_CASE_UNKNOWN")
            path=Path(__file__).parent/"examples"/name
            doc=_read(path.parent,path.name); result=adjudicate(doc["bundle"],doc["trusted_registry"],doc["policy"],doc["limits"])
            print(json.dumps(result,sort_keys=True,indent=2)); return 0
        if args.command=="adjudicate":
            result=adjudicate(_read(args.root,args.bundle),_read(args.root,args.registry),_read(args.root,args.policy),{})
            _write(args.root,args.out,result); return 0
        result=verify(_read(args.root,args.record),_read(args.root,args.registry),_read(args.root,args.bundle),_read(args.root,args.policy))
        print(json.dumps(result,sort_keys=True)); return 0 if result["valid"] else 3
    except (OSError,UnicodeError,json.JSONDecodeError,ValueError,AdjudicationError) as exc:
        print(json.dumps({"status":"ERROR","code":getattr(exc,"code",str(exc))},sort_keys=True),file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
