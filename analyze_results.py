#!/usr/bin/env python3
"""
Correlazione delle segnalazioni con la ground truth e calcolo delle metriche
per il confronto del capitolo 4 della tesi.
Legge:
  - la ground truth prodotta da generate_traffic.py
  - l'output di Suricata (eve.json)
  - l'output di Zeek con lo script predefinito detect-sql-injection (http.log)
  - l'output di Zeek con lo script default deny whitelist.zeek (http.log)
Per ogni richiesta l'associazione avviene tramite il parametro tid, che
generate_traffic.py inserisce nell'URI di ogni richiesta (anche POST).
"""
import argparse
import csv
import json
import re
# Classi considerate come attacco
EXPLOIT_CLASSES = {"sqli_logic", "sqli_union", "sqli_blind", "sqli_time", "sqli_obfuscated"}
# Classi considerate traffico legittimo
NEGATIVE_CLASSES = {"benigne", "sospette"}
# Classe di sondaggio delle vulnerabilità, esclusa dal conteggio principale
PROBE_CLASS = "sqli_probe"
# Classe di traffico legittimo ma atipico.
ATYPICAL_CLASS = "sospette"
# Suricata: bisogna escludere i rilevamenti di due regole.
# (1) Rilevamenti del motore Suricata (decoder/stream/http/app-layer events) che scattano
#     su anomalie di rete (es. il checksum TCP non valido per checksum offloading). 
#     Non sono rilevamenti di attacco e vengono esclusi dal conteggio.
EXCLUDE_ENGINE_PATTERNS = ["suricata "] #iniziano così le regole di suricata
# (2) Regole che identificano il client (User-Agent) e non l'attacco.
EXCLUDE_UA_PATTERNS = ["python-requests"]
# Zeek default deny: tag dello script whitelist.zeek aggiunto in http.log alle richieste anomale.
ANOMALY_TAG = "URI_POLICY"
# Zeek predefinito: tag dello script predefinito Zeek.
SQLI_TAG = "URI_SQLI"
# Regex per isolare il tid dall'URI
TID_RE = re.compile(r"[?&]tid=(\d+)")
def extract_tid(text):
    """Estrae il tid dall'URI."""
    if not text:
        return None
    m = TID_RE.search(text)
    if m:
        return int(m.group(1))
    else:
        return None
# Caricamento ground truth
def load_ground_truth(path):
    gt = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            gt[int(row["tid"])] = {"class": row["class"], "method": row["method"],"path": row["path"]}
    return gt
# Suricata: eve.json (una riga JSON per evento)  
def parse_suricata(path):
    """Restituisce la lista degli allarmi come (tid, signature_id, signature).
    L'associazione fra le segnalazioni e le richieste avviene attraverso
    l'identificativo tid, estratto dall'URI riportata nel log. Alcuni allarmi
    non riportano nel proprio record all'interno di eve.json l'URI della
    richiesta e quindi il tid necessario alla correlazione. Ogni richiesta, però,
    produce anche un evento http che contiene sempre l'URI. Ogni richiesta
    viene inoltre inviata su una connessione TCP dedicata, quindi ogni flusso,
    è caratterizzato da un certo flow_id e contiene una sola richiesta HTTP e
    dunque un solo tid. Si costruisce perciò una mappa flow_id -> tid,
    attraverso la quale gli allarmi privi di URI vengono ricondotti alla
    richiesta che li ha originati."""
    events = []
    flow_tid = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(ev)
            if ev.get("event_type") == "http":
                fid = ev.get("flow_id")
                t = extract_tid((ev.get("http") or {}).get("url"))
                if fid is not None and t is not None:
                    flow_tid[fid] = t
    alerts = []
    for ev in events:
        if ev.get("event_type") != "alert":
            continue
        tid = flow_tid.get(ev.get("flow_id"))
        if tid is None:
            continue
        al = ev.get("alert") or {}
        alerts.append((tid, al.get("signature_id"), al.get("signature", "")))
    return alerts
    
def is_engine_event(signature):
    s = (signature or "").lower()
    return any(p in s for p in EXCLUDE_ENGINE_PATTERNS)

def is_ua_signature(signature):
    s = (signature or "").lower()
    return any(p in s for p in EXCLUDE_UA_PATTERNS)

# Zeek: http.log (formato TSV nativo)
def parse_zeek_http(path):
    """Ritorna la lista delle richieste come (tid, [tag, ...], uri)."""
    fields = None
    out = []
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):          # mi serve la riga di intestazione
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):                # le righe che iniziano con # non servono
                continue
            if fields is None:
                continue
            rec = dict(zip(fields, line.split("\t")))
            uri = rec.get("uri", "")
            tid = extract_tid(uri)
            if tid is None:
                continue
            raw_tags = rec.get("tags", "-")
            if raw_tags in ("(empty)", "-", ""):
                tags = []
            else:
                tags = [t.split("::")[-1] for t in raw_tags.split(",")]
            out.append((tid, tags, uri))
    return out

def _norm_tag(t):
    # Zeek scrive il prefisso del modulo nei log (es. HTTP::URI_SQlI)
    # si normalizza tenendo solo la parte dopo "::"
    return t.rsplit("::", 1)[-1]

def detected_tids_by_tag(records, tag):
    wanted = _norm_tag(tag)
    return {tid for tid, tags, _ in records if wanted in {_norm_tag(t) for t in tags}}
    
# Metriche
def confusion(gt, detected):
    """TP/FP/FN/TN sul conteggio principale (attacco vs legittimo)"""
    tp = fp = fn = tn = 0
    for tid, info in gt.items():
        cls = info["class"]
        det = tid in detected
        if cls in EXPLOIT_CLASSES:
            tp += det
            fn += not det
        elif cls in NEGATIVE_CLASSES:
            fp += det
            tn += not det
    return tp, fp, fn, tn

def metrics(tp, fp, fn, tn):
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * prec * tpr / (prec + tpr)) if (prec + tpr) else 0.0
    return tpr, fpr, prec, f1

def fmt(x):
    return f"{x:.2f}".replace(".", ",")
    
def load_all(args):
    """Legge ground truth, log, e calcola gli insiemi di tid rilevati."""
    gt = load_ground_truth(args.gt) #ground_truth
    suri = parse_suricata(args.suricata) #suricata
    zf = parse_zeek_http(args.zeek_firme) #zeek_firme
    za = parse_zeek_http(args.zeek_anomalie) #zeek_anomalie
    det_suri_net = {tid for tid, _, sig in suri if not is_engine_event(sig) and not is_ua_signature(sig)}
    det_zf = detected_tids_by_tag(zf, SQLI_TAG)
    det_za = detected_tids_by_tag(za, ANOMALY_TAG)
    return gt, suri, zf, za, det_suri_net, det_zf, det_za

def print_diagnostica(gt, suri, zf, za, det_zf, det_za):
    print("=" * 70)
    print("DIAGNOSTICA")
    print("=" * 70)

    sigs = {}
    for tid, sid, sig in suri:
        sigs.setdefault((sid, sig), 0)
        sigs[(sid, sig)] += 1
    print("Firme Suricata che hanno fatto match (sid | n | categoria | firma):")
    for (sid, sig), n in sorted(sigs.items(), key=lambda x: -x[1]):
        if is_engine_event(sig):
            lab = "motore  (escluse)"
        elif is_ua_signature(sig):
            lab = "UA      (escluse)"
        else:
            lab = "ATTACCO (conteggiata)   "
        print(f"  {str(sid):>8} | {n:>4} | {lab} | {sig}")

    tags_seen = set()
    for _, tags, _ in zf + za:
        tags_seen.update(tags)
    print(f"\nTag Zeek osservati nelle http.log: {sorted(tags_seen)}")
    zf_uri = {}
    for tid, _, uri in zf:
        zf_uri[tid] = uri
    za_uri = {}
    for tid, _, uri in za:
        za_uri[tid] = uri

    print("\nFalsi positivi del default-deny sul traffico legittimo (classe | tid | uri):")
    fp_anom = []
    for tid in det_za:
        classe = gt.get(tid, {}).get("class")
        if classe in NEGATIVE_CLASSES:
            fp_anom.append(tid)
    fp_anom = sorted(fp_anom)
    if not fp_anom:
        print("  nessuno")
    for t in fp_anom:
        print(f"  {gt[t]['class']:13} | {t:>3} | {za_uri.get(t, '')}")

    print("\nAttacco via GET non rilevato da Zeek-firme (tid | uri):")
    missed = []
    for t in gt:
        if gt[t]['class'] in EXPLOIT_CLASSES and gt[t]['method'] == 'GET' and t not in det_zf:
            missed.append(t)
    missed = sorted(missed)
    if not missed:
        print("  nessuno")
    for t in missed:
        print(f"  {t:>3} | {zf_uri.get(t, '')}")

    suri_by_tid = {}
    for tid, sid, sig in suri:
        if is_engine_event(sig):
            continue
        suri_by_tid.setdefault(tid, [])
        if (sid, sig) not in suri_by_tid[tid]:
            suri_by_tid[tid].append((sid, sig))

    print("\nRegole Suricata per richiesta di attacco (esclusi UA_requests-TCP_checksum):")
    any_exploit = False
    for t in sorted(x for x, i in gt.items() if i["class"] in EXPLOIT_CLASSES):
        for sid, sig in suri_by_tid.get(t, []):
            if is_ua_signature(sig):
                continue
            any_exploit = True
            print(f"  tid {t:>3} ({gt[t]['class']}, {gt[t]['method']}): {sid} | {sig}")
    if not any_exploit:
        print("  nessuna")

    print("\nRegole Suricata sul traffico legittimo (esclusi UA_requests-TCP_checksum):")
    any_fp = False
    for t in sorted(x for x, i in gt.items() if i["class"] in NEGATIVE_CLASSES):
        for sid, sig in suri_by_tid.get(t, []):
            if is_ua_signature(sig):
                continue
            any_fp = True
            print(f"  tid {t:>3} ({gt[t]['class']}): {sid} | {sig}")
    if not any_fp:
        print("  nessuna")
        
def print_tabella_esiti(gt, det_suri, det_zf, det_za):
    print("\n" + "=" * 70)
    print("TABELLA — esito per singola richiesta di attacco")
    print("=" * 70)
    exploit = sorted(t for t, i in gt.items() if i["class"] in EXPLOIT_CLASSES)
    print(f"{'tid':>4} {'classe':16} {'meth':4} {'Suricata':>5} {'Zsign':>5} {'Zanomaly':>5}")
    for tid in exploit:
        info = gt[tid]
        s = "sì" if tid in det_suri else "no"
        f = "sì" if tid in det_zf else "no"
        a = "sì" if tid in det_za else "no"
        print(f"{tid:>4} {info['class']:16} {info['method']:4} {s:>5} {f:>5} {a:>5}")

def print_tabella_metriche(gt, configs):
    print("\n" + "=" * 70)
    print("TABELLA — metriche sui soli tentativi di attacco")
    print("=" * 70)
    print(f"{'configurazione':32} {'TP':>3} {'FP':>3} {'FN':>3} "
          f"{'TPR':>5} {'FPR':>5} {'F1':>5}")
    for name, det in configs:
        tp, fp, fn, tn = confusion(gt, det)
        tpr, fpr, prec, f1 = metrics(tp, fp, fn, tn)
        print(f"{name:32} {tp:>3} {fp:>3} {fn:>3} "
              f"{fmt(tpr):>5} {fmt(fpr):>5} {fmt(f1):>5}")

def print_tabella_sondaggi(gt, configs):
    print("\n" + "=" * 70)
    print("TABELLA — sondaggi e falsi allarmi sul traffico atipico")
    print("=" * 70)
    probes = {t for t, i in gt.items() if i["class"] == PROBE_CLASS}
    atypical = {t for t, i in gt.items() if i["class"] == ATYPICAL_CLASS}
    np_, na = len(probes), len(atypical)
    print(f"{'configurazione':32} {'sondaggi':>9} {'falsi atipici':>14}")
    for name, det in configs:
        ps = len(probes & det)
        fa = len(atypical & det)
        print(f"{name:32} {f'{ps}/{np_}':>9} {f'{fa}/{na}':>14}")

def main():
    ap = argparse.ArgumentParser(description="Correlazione e metriche del confronto IDS.")
    ap.add_argument("--gt", default="ground_truth.csv")
    ap.add_argument("--suricata", default="out-suricata/eve.json")
    ap.add_argument("--zeek-firme", default="out-zeek-firme/http.log")
    ap.add_argument("--zeek-anomalie", default="out-zeek-anomalie/http.log")
    args = ap.parse_args()
    gt, suri, zf, za, det_suri_net, det_zf, det_za = load_all(args)
    configs = [
        ("Suricata + ET", det_suri_net),
        ("Zeek + detect-sql-injection", det_zf),
        ("Zeek + default deny", det_za),]
    print_diagnostica(gt, suri, zf, za, det_zf, det_za)
    print_tabella_esiti(gt, det_suri_net, det_zf, det_za)
    print_tabella_metriche(gt, configs)
    print_tabella_sondaggi(gt, configs)

if __name__ == "__main__":
    main()
