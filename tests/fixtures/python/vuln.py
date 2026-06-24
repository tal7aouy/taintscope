import os
import subprocess
import sqlite3


def sqli_basic(conn):
    # Flask-style request.args flows into a SQL execute.
    user_id = request.args['id']
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s" % user_id)


def rce_basic():
    cmd = request.args['cmd']
    os.system(cmd)


def rce_interprocedural():
    # Taint flows through a helper into a sink.
    data = request.args['data']
    run(data)


def run(arg):
    subprocess.run(arg, shell=True)


def lfi_basic():
    path = request.args['file']
    open(path)


def safe_int():
    # Sanitized via int() -> should NOT report SQLi.
    raw = request.args['n']
    n = int(raw)
    conn = sqlite3.connect(':memory:')
    conn.execute("SELECT * FROM t WHERE id = %d" % n)
