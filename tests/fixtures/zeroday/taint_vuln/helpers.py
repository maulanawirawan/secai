import subprocess

from flask import request


def run_report(report):
    subprocess.run("generate-report --name " + report, shell=True)


def get_expr():
    return request.args.get("expr", "1+1")
