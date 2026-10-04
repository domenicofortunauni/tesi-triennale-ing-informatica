##! Rilevamento di anomalie di tipo default deny sulle richieste HTTP.
##! sono ammessi soltanto gli endpoint elencati, i metodi previsti per ciascuno di essi, 
##! gli attributi attesi, i valori e le lunghezze ammissibili.
##! Ogni anomalia produce un tag in http.log e una notifica in notice.log.
##! La verifica viene eseguita sia sull'URI che nel corpo della richiesta
##! Uso:  zeek -r traffico.pcap ./whitelist.zeek

@load base/protocols/http
@load base/frameworks/notice

module HTTP;

export {
	redef enum Notice::Type += {
		Policy_Violation
	};
	redef enum Tags += {
		URI_POLICY
	};
	
	## Specifica dei valori ammissibili sia per i
	## parametri dell'URI sia per i campi del corpo.
	type ParamSpec: record {
	
		## caratteri ammessi, denotati da una regex
		allowed: pattern;
		
		## Lunghezza massima del valore, in caratteri.
		max_len: count &default = 64;
	};

	## Costante ridefinibile per eventualmente valutare soltanto l'URI.
	const inspect_body: bool = T &redef;

	## Limite sulla dimensione massima del corpo di una richiesta.
	const max_body: count = 8192 &redef;

	## Endpoint esposti dal servizio.
	const allowed_paths: set[string] = {
		"/",
		"/api/v1/search",
		"/api/v1/session",
		"/assets/main.css",
		"/assets/app.js",
		"/favicon.ico",
	} &redef;

	## Metodi HTTP previsti per ciascun endpoint. Un metodo non elencato,
	## come DELETE, PUT o OPTIONS, costituisce una anomalia.
	
	const allowed_methods: table[string] of set[string] = {
		["/"]                = set("GET"),
		["/api/v1/search"]   = set("GET"),
		["/api/v1/session"]  = set("POST"),
		["/assets/main.css"] = set("GET"),
		["/assets/app.js"]   = set("GET"),
		["/favicon.ico"]     = set("GET"),
	} &redef;

	## parametri ammessi per ogni endpoint.
	## Il parametro per la correlazione tid viene dichiarato qui.
	## Se non venisse dichiarato, ogni richiesta risulterebbe anomala.
	
	const global_params: table[string] of ParamSpec = {
		["tid"] = [$allowed = /[0-9]+/, $max_len = 6],
	} &redef;

	## Parametri ammessi nell'URI della richiesta per endpoint.
	const endpoint_params: table[string, string] of ParamSpec = {
		["/api/v1/search", "name"] = [$allowed = /[a-zA-Z0-9 ,.'\-]*/,
		                              $max_len = 40],
	} &redef;

	## Parametri ammessi nel corpo della richiesta per endpoint.
	const body_params: table[string, string] of ParamSpec = {
		["/api/v1/session", "username"] = [$allowed = /[a-zA-Z0-9._\-]*/,
		                                   $max_len = 32],
		["/api/v1/session", "password"] = [$allowed = /[a-zA-Z0-9._\-!?@#]*/,
		                                   $max_len = 32],
	} &redef;
}

## Corpo della richiesta "accumulato", non viene scritto in http.log
## serve per poter analizzare il corpo della richiesta.
redef record Info += {
	dd_body: string &default = "";
};

## Funzione che segnala una anomalia, il campo $sub riporta il motivo in forma
## leggibile, così da poter distinguere nei risultati cosa ha prodotto la segnalazione
## L'identificatore $identifier non viene impostato di proposito: con esso
## il framework Notice sopprimerebbe i duplicati per un'ora, producendo una
## sola notifica per host anziché una per richiesta.
function violation(c: connection, reason: string, detail: string) {
	if ( ! c?$http )
		return;
	# Una sola notifica di anomalia per richiesta, anche se più controlli falliscono.
	if ( URI_POLICY in c$http$tags )
		return;
	add c$http$tags[URI_POLICY];
	NOTICE([$note = Policy_Violation,
	        $conn = c,
	        $msg = fmt("Richiesta fuori dal modello di normalita': %s", reason),
	        $sub = detail]);
	}
## Verifica se un parametro è conforme alla specifica di normalità.
## Se non lo è invoca la funzione violation per segnalare l'anomalia
function check_value(c: connection, fname: string, fval: string, spec: ParamSpec) {
	if ( |fval| > spec$max_len )
		violation(c, "valore troppo lungo",
		          fmt("%s (%d caratteri, massimo %d)", fname, |fval|, spec$max_len));
	else if ( spec$allowed != fval )
		violation(c, "caratteri non ammessi",
		          fmt("%s=%s", fname, fval));
	}
## Estrae il percorso dall'URI, scartando la parte di query.
function path_of(uri: string): string {
	return split_string1(uri, /\?/)[0];
	}
## Verifica i parametri della parte query dell'URI.
function check_query(c: connection, path: string, query: string) {
	local items = split_string(query, /&/);
	#split sui parametri
	for ( i in items ) {
	#ogni parametro viene diviso in una coppia in base all'uguale prima di essere decodificato
		local kv = split_string1(items[i], /=/);
		local pname = unescape_URI(gsub(kv[0], /\+/, " "));
		local pval = |kv| > 1 ? kv[1] : "";
		pval = unescape_URI(gsub(pval, /\+/, " "));
		if ( pname in global_params )
			check_value(c, pname, pval, global_params[pname]);
		else if ( [path, pname] in endpoint_params )
			check_value(c, pname, pval, endpoint_params[path, pname]);
		else
			violation(c, "campo non previsto nella query string",
			          fmt("%s sull'endpoint %s", pname, path));
		}
	}
## Verifica i campi del corpo, sottoponendoli alla stessa logica applicata ai parametri dell'URI.
## Il controllo non costituisce un parser JSON, è tarato agli oggetti utilizzati dal servizio ({"campo": "valore", ...}),
## non gestisce né le virgolette all'interno dei valori né valori come numeri, booleani, null, oggetti annidati, 
## che nell'app non compaiono.
function check_body(c: connection, path: string, body: string) {
	local fields = find_all(body, /\"[^\"]+\"[[:blank:]]*:[[:blank:]]*\"[^\"]*\"/);
	for ( f in fields ) {
		local halves = split_string1(f, /\"[[:blank:]]*:[[:blank:]]*\"/);
		if ( |halves| < 2 )
			next;
		local fname = sub(halves[0], /^\"/, "");
		local fval = sub(halves[1], /\"$/, "");
		if ( [path, fname] in body_params )
			check_value(c, fname, fval, body_params[path, fname]);
		else
			violation(c, "campo non previsto nel corpo",
			          fmt("%s sull'endpoint %s", fname, path));
		}
	}
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
	# L'URI viene divisa nei suoi componenti prima di essere decodificata:
	# decodificarla per intero trasformerebbe un '&' o un '=' codificati
	# all'interno di un parametro in dei separatori, alterandoli.
	local parts = split_string1(original_URI, /\?/);
	local path = unescape_URI(parts[0]);
	local query = |parts| > 1 ? parts[1] : "";
	if ( path !in allowed_paths ) {
		violation(c, "endpoint non previsto", path);
		return;
	}
	if ( path in allowed_methods && method !in allowed_methods[path] ) {
		violation(c, "metodo non previsto per l'endpoint",
		          fmt("%s %s", method, path));
		return;
	}
	if ( query != "" )
		check_query(c, path, query);
	}
event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
	if ( ! inspect_body || ! is_orig || ! c?$http )
		return;
	if ( |c$http$dd_body| >= max_body )
		return;
	c$http$dd_body += data;
	}
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
	if ( ! inspect_body || ! is_orig || ! c?$http )
		return;
	if ( c$http$dd_body == "" || ! c$http?$uri )
		return;
	check_body(c, path_of(c$http$uri), c$http$dd_body);
	}
