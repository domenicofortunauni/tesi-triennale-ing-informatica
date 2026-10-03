#!/usr/bin/env python3
"""
Applicazione web sviluppata per la parte sperimentale della tesi che espone due endpoint per SQL injection:
  - /api/v1/search  (GET)   il parametro di ricerca finisce nella query senza sanitizzazione
  - /api/v1/session (POST)  username e password arrivano nel corpo JSON e concatenati dentro una SELECT di autenticazione.
Il parametro 'tid', quando presente nelle richieste, serve unicamente a correlare ogni richiesta con la ground truth per il calcolo delle metriche.
"""
import os
import pymysql
from flask import Flask, request, jsonify, render_template

# I file della cartella static/ sono serviti sotto /assets/, gli stessi
# percorsi usati nell'esperimento e ammessi da whitelist.zeek.
app = Flask(__name__, static_url_path="/assets")

# Configurazione della connessione al database con lettura delle variabili dal file docker-compose
DB_HOST = os.environ["DB_HOST"]
DB_PORT = int(os.environ["DB_PORT"])
DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DB_NAME = os.environ["DB_NAME"]

def get_conn():
    """Apre una connessione per ogni richiesta. autocommit attivo."""
    return pymysql.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER,
        password=DB_PASSWORD, database=DB_NAME,
        autocommit=True, charset="utf8mb4",
    )

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/favicon.ico")
def favicon():
    return app.response_class(b"", mimetype="image/x-icon")

# Punto di iniezione 1: ricerca prodotti (GET, input nell'URI)
# il parametro di ricerca è concatenato direttamente nella query.

@app.route("/api/v1/search")
def search():
    name = request.args.get("name", "")
    query = (
        "SELECT id, name, price, '', '', '' "
        "FROM products WHERE name LIKE '%" + name + "%'"
    )
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
        conn.close()
    except pymysql.MySQLError as e:
        return jsonify({"error": str(e), "query": query}), 500
    results = [{"col0": r[0], "col1": r[1], "col2": r[2]} for r in rows]
    return jsonify({"count": len(results), "results": results})

# Punto di iniezione 2: autenticazione (POST, input nel corpo JSON)
# username e password sono concatenati nella query.

@app.route("/api/v1/session", methods=["POST"])
def session():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    query = (
        "SELECT id, username, role FROM users "
        "WHERE username = '" + username + "' "
        "AND password = '" + password + "'"
    )
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute(query)
            row = cur.fetchone()
        conn.close()
    except pymysql.MySQLError as e:
        return jsonify({"error": str(e), "query": query}), 500
    if row:
        return jsonify({"authenticated": True,
                        "user_id": row[0],
                        "username": row[1],
                        "role": row[2]})
    return jsonify({"authenticated": False}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
