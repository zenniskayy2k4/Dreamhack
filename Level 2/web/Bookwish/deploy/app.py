#!/usr/bin/env python3
import os
from threading import RLock
from flask import Flask, render_template, request, redirect
import pymysql

app = Flask(__name__)
app.secret_key = os.urandom(32)

def db_connect():
    db = pymysql.connect(host = "localhost",
                         port = 3306,
                         user = "user",
                         passwd = "passwd",
                         db = "book_db",
                         charset = "utf8")
    cursor = db.cursor()
    return db, cursor

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        try:
            title = request.form.get("title")
            author = request.form.get("author")
            with lock:
                cursor.execute('INSERT INTO requests (book_title, author) select \'{0}\', \'{1}\' where not exists (SELECT 1 FROM requests WHERE book_title=\'{0}\' AND author=\'{1}\');'.format(title, author))
                db.commit()
            return render_template("index.html", msg="Thank you! Your request submitted successfully.")
        except Exception as e:
            print(e, flush=True)
            return render_template("index.html", msg="Error occurred. Try again.")
    else:
        return render_template("index.html")

if __name__ == "__main__":
    lock = RLock()
    db, cursor = db_connect()
    app.run(host = "0.0.0.0", port=8000)
    db.close()
