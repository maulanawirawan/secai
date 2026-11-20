import sqlite3


def find_user(name):
    cur = sqlite3.connect("app.db").cursor()
    query = "SELECT * FROM users WHERE name = '%s'" % name
    cur.execute(query)
    return cur.fetchall()
