"""FP-CONTROL fixture for tools/taint_engine.py: the same routes as
taint_vuln, written safely. The engine must report NOTHING here."""
import html
import os
import shlex
import sqlite3
import subprocess

import requests
import yaml
from flask import (Flask, redirect, render_template_string, request,
                   send_from_directory, url_for)
from markupsafe import Markup

app = Flask(__name__)
API = "https://api.internal.example/v1/search"


@app.route("/user")
def user():
    name = request.args.get("name", "")
    cur = sqlite3.connect("a.db").cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return str(cur.fetchall())


@app.route("/id")
def by_id():
    uid = int(request.args["id"])
    cur = sqlite3.connect("a.db").cursor()
    cur.execute("SELECT * FROM t WHERE id = %d" % uid)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args["host"]
    subprocess.run(["ping", "-c", "1", host], check=False)
    os.system("ping -c 1 " + shlex.quote(host))
    return "ok"


@app.route("/hello/<name>")
def hello(name):
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)


@app.route("/conf", methods=["POST"])
def conf():
    a = yaml.safe_load(request.data)
    b = yaml.load(request.data, Loader=yaml.SafeLoader)
    return str((a, b))


@app.route("/search")
def search():
    q = request.args.get("q")
    return requests.get(API, params={"q": q}, timeout=5).text


@app.route("/file")
def file():
    return send_from_directory("/srv/files", request.args.get("f"))


@app.route("/go")
def go():
    return redirect(url_for("user"))


@app.route("/msg")
def msg():
    return Markup(html.escape(request.args.get("m", "")))


@app.route("/reassign")
def reassign():
    x = request.args.get("x")
    x = "constant"
    os.system("echo " + x)
    return "ok"


@app.route("/item/<int:item_id>")
def item(item_id):
    with open(f"/srv/items/{item_id}.json") as fh:
        return fh.read()
