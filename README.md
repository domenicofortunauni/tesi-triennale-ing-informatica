# Confronto sperimentale tra Suricata e Zeek nel rilevamento di SQL injection

Laboratorio della tesi.
Mette a confronto due sistemi di rilevamento delle intrusioni (IDS) sullo stesso traffico,
per osservare come il principio di rilevamento e la parte di richiesta analizzata 
influenzino l'individuazione degli attacchi di tipo SQL injection.

Lo stesso file di cattura viene analizzato con **tre configurazioni**:

1. **Suricata** con il ruleset Emerging Threats Open — rilevamento basato su firme;
2. **Zeek** con lo script predefinito `detect-sql-injection` — firme (espressioni
   regolari) applicate al solo URI;
3. **Zeek** con lo script `whitelist.zeek` — rilevamento basato sulle anomalie,
   di tipo *default deny*: si descrive il comportamento normale del servizio e si
   segnala ogni scostamento dal profilo normale.

## L'ambiente di laboratorio

L'ambiente è un'applicazione web volontariamente vulnerabile a SQL injection, usata
solo come bersaglio. Espone due punti vulnerabili:

- `GET /api/v1/search` — il parametro `name` è concatenato nella query senza
  sanitizzazione (iniezione nell'URI);
- `POST /api/v1/session` — `username` e `password` inviati nel corpo JSON, vengono
  concatenati in una SELECT di autenticazione (iniezione nel corpo).

Il traffico è generato da uno script che riproduce il comportamento di un attaccante 
(navigazione, sondaggio, attacco, varianti offuscate) e che comprende richieste lecite
ma insolite che permettono di valutare i falsi positivi.

## Struttura del repository

```
app.py                  applicazione Flask vulnerabile
templates/, static/     pagina e risorse del servizio
Dockerfile              immagine dell'applicazione
docker-compose.yml      applicazione + database MariaDB
init.sql                schema e dati di esempio del database

generate_traffic.py     genera il traffico e produce la ground truth
whitelist.zeek          script Zeek default deny
analyze_results.py      correla gli allarmi con la ground truth e calcola le metriche

captures/traffico.pcap  cattura del traffico di valutazione
ground_truth.csv        classe per ogni richiesta
out-suricata/           output di Suricata (eve.json, ...)
out-zeek-firme/         output di Zeek con lo script predefinito
out-zeek-anomalie/      output di Zeek con lo script default deny
out.txt                 risultato di analyze_results.py

analisi-regole/         elenco delle regole ET Open sulle SQL injection
```

## Strumenti utilizzati

L'esperimento è stato eseguito con:

- **Suricata** (immagine `jasonish/suricata`)
- **Zeek** (immagine `zeek/zeek`)
- **MariaDB** (immagine `mariadb:11.4`)
- **Ruleset Emerging Threats Open**, versione di settembre 2026, scaricato il
  20/09/2026 con `suricata-update`: **52.823 regole abilitate**. Le regole che ET
  lascia disabilitate di default (15.956, di cui 519 relative alle SQL injection)
  non sono abilitate nella configurazione predefinita.


Prerequisiti: Docker con il plugin Compose e Python 3 con la libreria `requests`.

### 1. Avvio dell'applicazione

```bash
docker compose up --build -d
```

L'applicazione resta in ascolto su `http://localhost:8080`

### 2. Cattura del traffico e generazione

In un terminale, avviare la cattura sull'interfaccia bridge che Docker Compose
crea per i container. Il nome dell'interfaccia dipende dalla rete e si ricava con
`docker network ls` (è nella forma `br-xxxxxxxxxxxx`):

```bash
sudo tcpdump -i br-xxxxxxxxxxxx -nn -s 0 -w captures/traffico.pcap 'tcp port 5000'
```

In un altro terminale, generare il traffico; al termine, fermare `tcpdump`:

```bash
python3 generate_traffic.py mixed --base http://localhost:8080
```

Lo script scrive `ground_truth.csv`, con una riga per ogni richiesta e la sua classe.

### 3. Analisi con le tre configurazioni

**Suricata.** Scaricare il ruleset e analizzare la cattura:

```bash
# Scaricamento del ruleset Emerging Threats Open
docker run --rm -v "$PWD/suricata:/var/lib/suricata" \
    jasonish/suricata:latest suricata-update

# Analisi del file pcap
docker run --rm \
    -v "$PWD/suricata:/var/lib/suricata" \
    -v "$PWD:/laboratorio_tesi" \
    jasonish/suricata:latest \
    suricata -k none -S /var/lib/suricata/rules/suricata.rules \
        --set 'vars.port-groups.HTTP_PORTS=[80,5000]' \
        --set 'vars.address-groups.EXTERNAL_NET=any' \
        -r /laboratorio_tesi/captures/traffico.pcap \
        -l /laboratorio_tesi/out-suricata
```

`EXTERNAL_NET=any` e l'aggiunta della porta 5000 sono necessari perché nel
laboratorio le richieste provengono da un indirizzo privato (quello di Docker) e
sono dirette alla porta 5000.

**Zeek, script predefinito:**

```bash
docker run --rm -v "$PWD:/laboratorio_tesi" \
    -w /laboratorio_tesi/out-zeek-firme \
    zeek/zeek:latest \
    zeek -C -r /laboratorio_tesi/captures/traffico.pcap \
        protocols/http/detect-sql-injection
```

**Zeek, script default deny:**

```bash
docker run --rm -v "$PWD:/laboratorio_tesi" \
    -w /laboratorio_tesi/out-zeek-anomalie \
    zeek/zeek:latest \
    zeek -C -r /laboratorio_tesi/captures/traffico.pcap \
        /laboratorio_tesi/whitelist.zeek
```

`-C` disabilita la verifica del checksum (checksum offloading), così come il `-k none` in
Suricata.

### 4. Calcolo delle metriche

```bash
python3 analyze_results.py > out.txt
```

Lo script correla gli allarmi delle tre configurazioni con `ground_truth.csv`
tramite il marcatore `tid` presente in ogni richiesta, e stampa una sezione
diagnostica seguita dalle tre tabelle dei risultati.

## Risultati di riferimento

Metriche sui 33 tentativi di attacco (dettaglio in `out.txt`):

| Configurazione                     | TP | FP | FN | TPR  | FPR  | F1   |
|------------------------------------|---:|---:|---:|-----:|-----:|-----:|
| Suricata + ET                      |  7 |  6 | 26 | 0,21 | 0,07 | 0,30 |
| Zeek + detect-sql-injection        | 20 |  0 | 13 | 0,61 | 0,00 | 0,75 |
| Zeek + default deny                | 33 | 14 |  0 | 1,00 | 0,17 | 0,82 |

Per Suricata, viene indicato il conteggio senza gli allarmi legati al checksum TCP non valido e la
regola che riconosce lo User-Agent della libreria `requests`, che scatterebbe su tutte le richieste.
