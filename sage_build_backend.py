"""Small deterministic PEP 517 backend using only Python's standard library."""
from __future__ import annotations
import base64,csv,datetime,gzip,hashlib,io,json,os,tarfile,tomllib,zipfile
from pathlib import Path,PurePosixPath

ROOT=Path(__file__).resolve().parent
ALLOWLIST=ROOT/"SOURCE_ALLOWLIST.json"
DIST="sage_judge"
VERSION="0.1.0"
DIST_INFO=f"{DIST}-{VERSION}.dist-info"
WHEEL_NAME=f"{DIST}-{VERSION}-py3-none-any.whl"
SDIST_NAME=f"{DIST}-{VERSION}.tar.gz"
PACKAGE_FILES=(
 "src/sage_judge/__init__.py","src/sage_judge/__main__.py","src/sage_judge/api.py","src/sage_judge/cli.py","src/sage_judge/errors.py",
 "src/sage_judge/p01/__init__.py","src/sage_judge/p01/canonical.py","src/sage_judge/p01/errors.py","src/sage_judge/p01/evaluate.py","src/sage_judge/p01/impact.py","src/sage_judge/p01/proof.py","src/sage_judge/p01/registry.py","src/sage_judge/p01/sve.py","src/sage_judge/p01/typed_ir.py",
 "src/sage_judge/p02/__init__.py","src/sage_judge/p02/semantic_admission.py","src/sage_judge/p02/deterministic_comparator.py",
 "src/sage_judge/schemas/p01_sve_v1_1.schema.json","src/sage_judge/schemas/bundle.schema.json","src/sage_judge/schemas/decision_record.schema.json",
 "src/sage_judge/docs/API_CONTRACT.md","src/sage_judge/docs/ERROR_CATALOGUE.md","src/sage_judge/docs/EXTENDING_DOMAINS.md","src/sage_judge/docs/SCHEMA_REFERENCE.md",
 "src/sage_judge/examples/inspection_positive.json", "src/sage_judge/examples/inspection_unknown.json",
 "src/sage_judge/examples/inspection_conflict.json", "src/sage_judge/examples/unsupported_dependency.json")

def get_requires_for_build_wheel(config_settings=None): return []
def get_requires_for_build_sdist(config_settings=None): return []

def _load_allowlist():
 doc=json.loads(ALLOWLIST.read_text(encoding="utf-8"))
 if doc.get("candidate_version")!=VERSION or doc.get("release_profile")!="MIT" or doc.get("license_expression")!="MIT": raise ValueError("SOURCE_ALLOWLIST_HEADER_INVALID")
 files=doc.get("files")
 if not isinstance(files,dict) or not files: raise ValueError("SOURCE_ALLOWLIST_EMPTY")
 return files

def _read(relative,files):
 if relative not in files: raise ValueError("FILE_NOT_IN_CANDIDATE_ALLOWLIST:"+relative)
 parts=tuple(relative.split("/"))
 if str(PurePosixPath(relative))!=relative or any(x in {"",".",".."} or x.startswith(".") for x in parts): raise ValueError("NONCANONICAL_MEMBER_PATH")
 path=ROOT.joinpath(*parts)
 current=ROOT
 for part in parts:
  current=current/part
  if current.is_symlink(): raise ValueError("SYMLINK_SOURCE")
 st=path.lstat()
 if not path.is_file() or st.st_nlink!=1: raise ValueError("NONREGULAR_OR_ALIAS_SOURCE")
 raw=path.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=files[relative]: raise ValueError("SOURCE_HASH_MISMATCH:"+relative)
 return raw

def _metadata():
 p=tomllib.loads((ROOT/"pyproject.toml").read_text(encoding="utf-8"))["project"]
 if p["version"]!=VERSION or p["name"].replace("-","_")!=DIST: raise ValueError("PROJECT_METADATA_IDENTITY_MISMATCH")
 if p.get("license")!="MIT" or p.get("license-files")!=["LICENSE"] or p.get("dependencies")!=[] or p.get("requires-python")!=">=3.11": raise ValueError("PROJECT_RELEASE_METADATA_INVALID")
 _read("LICENSE",_load_allowlist())
 classifiers=p.get("classifiers",[])
 if any(c.startswith("Private ::") for c in classifiers): raise ValueError("PROJECT_RELEASE_CLASSIFIER_INVALID")
 return ("Metadata-Version: 2.4\nName: "+p["name"]+"\nVersion: "+VERSION+"\nSummary: "+p["description"]+"\nRequires-Python: "+p["requires-python"]+"\nLicense-Expression: MIT\nLicense-File: LICENSE\n"+"".join("Classifier: "+c+"\n" for c in classifiers)+"\n").encode()

def _zip_entry(z,name,data,epoch):
 dt=datetime.datetime.fromtimestamp(epoch,datetime.timezone.utc)
 zi=zipfile.ZipInfo(name,(dt.year,dt.month,dt.day,dt.hour,dt.minute,dt.second-(dt.second%2)))
 zi.compress_type=zipfile.ZIP_DEFLATED;zi.create_system=3;zi.external_attr=(0o100644<<16);zi.flag_bits=0
 z.writestr(zi,data,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)

def build_wheel(wheel_directory,config_settings=None,metadata_directory=None):
 files=_load_allowlist();epoch=int(os.environ.get("SOURCE_DATE_EPOCH","1795478400")); entries={}
 for name in PACKAGE_FILES: entries[name.removeprefix("src/")]=_read(name,files)
 entries[f"{DIST_INFO}/METADATA"]=_metadata()
 entries[f"{DIST_INFO}/licenses/LICENSE"]=_read("LICENSE",files)
 entries[f"{DIST_INFO}/WHEEL"]=b"Wheel-Version: 1.0\nGenerator: sage-judge-build/1\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
 entries[f"{DIST_INFO}/entry_points.txt"]=b"[console_scripts]\nsage-judge = sage_judge.cli:main\n"
 records=[]
 for name,data in sorted(entries.items()):
  digest=base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
  records.append((name,"sha256="+digest,str(len(data))))
 records.append((f"{DIST_INFO}/RECORD","",""))
 out=Path(wheel_directory)/WHEEL_NAME
 with zipfile.ZipFile(out,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  for name,data in sorted(entries.items()): _zip_entry(z,name,data,epoch)
  buff=io.StringIO(newline="");csv.writer(buff,lineterminator="\n").writerows(records)
  _zip_entry(z,f"{DIST_INFO}/RECORD",buff.getvalue().encode(),epoch)
 return WHEEL_NAME

def prepare_metadata_for_build_wheel(metadata_directory,config_settings=None):
 dest=Path(metadata_directory)/DIST_INFO;dest.mkdir(parents=True,exist_ok=False)
 (dest/"METADATA").write_bytes(_metadata())
 (dest/"licenses").mkdir()
 (dest/"licenses"/"LICENSE").write_bytes(_read("LICENSE",_load_allowlist()))
 (dest/"WHEEL").write_bytes(b"Wheel-Version: 1.0\nGenerator: sage-judge-build/1\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n")
 (dest/"entry_points.txt").write_bytes(b"[console_scripts]\nsage-judge = sage_judge.cli:main\n")
 return DIST_INFO

def build_sdist(sdist_directory,config_settings=None):
 files=_load_allowlist();epoch=int(os.environ.get("SOURCE_DATE_EPOCH","1795478400"));rootname=f"{DIST}-{VERSION}"
 out=Path(sdist_directory)/SDIST_NAME
 with out.open("xb") as raw:
  with gzip.GzipFile(filename="",mode="wb",fileobj=raw,mtime=epoch,compresslevel=9) as gz:
   with tarfile.open(fileobj=gz,mode="w|",format=tarfile.PAX_FORMAT) as tar:
    for rel in sorted(files):
     data=_read(rel,files);info=tarfile.TarInfo(f"{rootname}/{rel}")
     info.size=len(data);info.mtime=epoch;info.uid=0;info.gid=0;info.uname="";info.gname="";info.mode=0o644
     tar.addfile(info,io.BytesIO(data))
    allow_st=ALLOWLIST.lstat()
    if ALLOWLIST.is_symlink() or not ALLOWLIST.is_file() or allow_st.st_nlink!=1: raise ValueError("SOURCE_ALLOWLIST_NOT_REGULAR")
    allow_data=ALLOWLIST.read_bytes();info=tarfile.TarInfo(f"{rootname}/SOURCE_ALLOWLIST.json")
    info.size=len(allow_data);info.mtime=epoch;info.uid=0;info.gid=0;info.uname="";info.gname="";info.mode=0o644
    tar.addfile(info,io.BytesIO(allow_data))
    metadata=_metadata();info=tarfile.TarInfo(f"{rootname}/PKG-INFO");info.size=len(metadata);info.mtime=epoch;info.uid=0;info.gid=0;info.uname="";info.gname="";info.mode=0o644
    tar.addfile(info,io.BytesIO(metadata))
 return SDIST_NAME
