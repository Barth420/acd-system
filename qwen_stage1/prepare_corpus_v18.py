from pathlib import Path
import zipfile,csv,json,hashlib,re,collections,sys,datetime,os

HERE = Path(__file__).resolve().parent
ARCHIVE = "Windows-APT 2025 A Dataset for APT-Inspired Attack.zip"
OUT = Path(os.getenv("ACD_CORPUS_DIR", str(HERE / "data" / "processed"))).expanduser().resolve()
VAL=5
MAX_CHARS=10000
EXCLUDE_EXACT={"_id","_index","_version","_score","_source.id","_source.agent.id","_source.manager.name"}

def locate():
    configured = os.getenv("ACD_WINDOWS_APT_ARCHIVE")
    candidates = []
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.append(HERE / "data" / "raw" / ARCHIVE)
    candidates.append(HERE.parent / ARCHIVE)
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None

def clean(v):
    if v is None:return ""
    if isinstance(v,(dict,list)):s=json.dumps(v,ensure_ascii=False,sort_keys=True)
    else:s=str(v)
    s=re.sub(r"\s+"," ",s.replace("\x00"," ")).strip()
    return "" if s.lower() in ("nan","none","null","-") else s

def main():
    print("ACD V18 — FULLER EVENT SERIALIZATION; PRESERVE REPEATED OBSERVATIONS")
    a=locate()
    if not a:
        print("Archive not found. Set ACD_WINDOWS_APT_ARCHIVE to the source ZIP path.")
        sys.exit(2)
    OUT.mkdir(parents=True,exist_ok=True)
    tr=OUT/"windows_apt_train.jsonl";va=OUT/"windows_apt_validation.jsonl"
    tt=tr.with_suffix(".tmp");vt=va.with_suffix(".tmp")
    counts=collections.Counter(); fields=collections.Counter(); split_hashes=set()
    samples=[]
    with zipfile.ZipFile(a) as z:
        bad=z.testzip()
        if bad:print("CRC failure:",bad);sys.exit(3)
        member=next((n for n in z.namelist() if Path(n).name.lower()=="combined.csv"),None)
        if not member:print("combined.csv missing");sys.exit(4)
        with z.open(member) as raw,open(tt,"w",encoding="utf-8") as tf,open(vt,"w",encoding="utf-8") as vf:
            reader=csv.DictReader((b.decode("utf-8-sig",errors="replace") for b in raw))
            headers=reader.fieldnames or []
            # Keep informative source fields, exclude only technical identifiers and index metadata.
            chosen=[]
            for h in headers:
                hl=h.lower()
                if h in EXCLUDE_EXACT:continue
                if h.startswith("_source.") and any(x in hl for x in (
                    "timestamp","agent.name","rule.","decoder.","location","full_log",
                    "data.win.","predecoder.","input.type"
                )):
                    chosen.append(h)
            if not chosen:
                print("No useful _source fields found");sys.exit(5)
            for row in reader:
                counts["rows_read"]+=1
                parts=[]
                for h in chosen:
                    v=clean(row.get(h))
                    if v:
                        fields[h]+=1
                        # Shorten field names while retaining their original identity.
                        parts.append(f"{h}: {v}")
                text="\n".join(parts)[:MAX_CHARS].strip()
                if len(text)<40:
                    counts["short_or_empty_skipped"]+=1;continue
                digest=hashlib.sha256(text.encode("utf-8")).hexdigest()
                split_hashes.add(digest)
                bucket=int(digest[:8],16)%100
                obj={"text":text,"source_dataset":"Windows-APT-2025",
                     "label_status":"unlabelled",
                     "training_purpose":"cybersecurity_domain_adaptation"}
                line=json.dumps(obj,ensure_ascii=False)
                if bucket<VAL:
                    vf.write(line+"\n");counts["validation_records"]+=1
                else:
                    tf.write(line+"\n");counts["training_records"]+=1
                if len(samples)<5:samples.append(text[:600])
    tt.replace(tr);vt.replace(va)
    report=OUT/"windows_apt_corpus_v18_report.txt"
    manifest=OUT/"windows_apt_corpus_v18_manifest.json"
    info={"source_archive":str(a),"source_member":member,"rows":dict(counts),
          "unique_text_hashes":len(split_hashes),"selected_columns":chosen,
          "nonempty_counts":dict(fields),"validation_percent":VAL,
          "split":"deterministic content-hash grouping; duplicate text stays in one split",
          "deduplication":"No observations removed; repeated records retained.",
          "label_status":"unlabelled; domain adaptation only",
          "samples":samples}
    manifest.write_text(json.dumps(info,indent=2,ensure_ascii=False),encoding="utf-8")
    with open(report,"w",encoding="utf-8") as f:
        f.write("WINDOWS-APT V18 CORPUS PREPARATION\n")
        f.write(f"Rows read: {counts['rows_read']}\nTrain records: {counts['training_records']}\nValidation records: {counts['validation_records']}\n")
        f.write(f"Unique serialized text hashes: {len(split_hashes)}\nRepeated observations retained; no deduplication.\n")
        f.write(f"Selected columns: {len(chosen)}\n")
        f.write("All labels remain unlabelled. MITRE values are context, not ground-truth attack labels.\n")
        f.write(f"Train: {tr}\nValidation: {va}\nManifest: {manifest}\n")
    print("Rows read:",counts["rows_read"])
    print("Train:",counts["training_records"],"Validation:",counts["validation_records"])
    print("Unique text patterns:",len(split_hashes))
    print("Output:",OUT)

if __name__=="__main__":main()
