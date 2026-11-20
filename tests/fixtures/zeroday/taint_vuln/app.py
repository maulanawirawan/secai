"""DELIBERATELY VULNERABLE fixture for tools/taint_engine.py — never run."""
import os
import pickle

import requests
import yaml
from flask import Flask, redirect, render_template_string, request

import helpers
from db import find_user

app = Flask(__name__)


def get(key):  # same name as dict.get: must not swallow request.args.get
    return key


@app.route("/user")
def user():
    name = request.args.get("name", "")
    return str(find_user(name))  # cross-file -> db.py sqli


@app.route("/ping")
def ping():
    host = request.args["host"]
    cmd = "ping -c 1 " + host
    os.system(cmd)
    return "ok"


@app.route("/run", methods=["POST"])
def run():
    helpers.run_report(request.form.get("report"))  # -> helpers.py cmdi
    return "ok"


@app.route("/hello/<name>")
def hello(name):
    return render_template_string(f"<h1>Hello {name}</h1>")


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))


@app.route("/conf", methods=["POST"])
def conf():
    return str(yaml.load(request.data))


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text


@app.route("/file")
def file():
    fname = request.args.get("f")
    path = os.path.join("/srv/files", fname)
    with open(path) as fh:
        return fh.read()


@app.route("/go")
def go():
    return redirect(request.args.get("next"))


@app.route("/calc")
def calc():
    expr = helpers.get_expr()  # helper RETURNS request data
    return str(eval(expr))
