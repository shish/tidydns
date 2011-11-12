#!/usr/bin/python

import web
web.config.debug = False

import cgi
import logging
import logging.handlers

import re
import os
import sqlite3
import time
import base64
import hashlib

import cgitb; cgitb.enable()

urls = (
    '/?', 'index',
    '/(.*)', 'update',
)
#render = web.template.render("../templates/")
app = web.application(urls, globals())
#session = web.session.Session(
#    app, web.session.DiskStore('../sessions/'),
#    initializer={'username': None})


class index:
    def GET(self):
        return file("index.html").read()
 
class update:
    def GET(self, name):
        web.header('Content-Type', 'text/plain')
        if web.ctx.env.get('HTTP_AUTHORIZATION') is None:
            return "no username / password specified"
        elif not valid_name(web.ctx.env["REQUEST_URI"][1:]):
            return "invalid subdomain"
        else:
            return update_db(
                get_zone(web.ctx.env["HTTP_HOST"]),
                web.ctx.env["REQUEST_URI"][1:],
                get_ip(web.ctx.env["REMOTE_ADDR"]),
                web.ctx.env["HTTP_AUTHORIZATION"].split(" ")[1]
            )


def get_uid(auth, db):
    (username, password) = base64.b64decode(auth).split(":", 1)
    passhash = hashlib.md5("lol salt on a waffle "+password).hexdigest()

    users = list(db.execute("SELECT id,username,password FROM user WHERE username=?", [username, ]))
    if len(users) == 1:
        user = users[0]
        if user[2] == passhash:
            return user[0]
        else:
            return -1
    else:
        db.execute("INSERT INTO user(username, password) VALUES(?, ?)", [username, passhash])
        user = list(db.execute("SELECT id FROM user WHERE username=?", [username, ]))[0]
        return user[0]


def update_db(domain, new_name, new_address, auth):
    try:
        (username, password) = base64.b64decode(auth).split(":", 1)
    except:
        (username, password) = (None, None)
    logging.info("updating %s.%s = %s (from %s)" % (new_name, domain, new_address, username))
    db_conn = sqlite3.connect('../db/ddns.db')

    try:
        # startup
        db = db_conn.cursor()
        uid = get_uid(auth, db)
        if uid == -1:
            return "failed: username / password mismatch"

        # update database
        records = list(db.execute("SELECT user_id FROM record WHERE name=? AND domain=?", [new_name, domain]))
        if len(records) == 1:
            record = records[0]
            if record[0] == uid:
                db.execute(
                    "UPDATE record SET address=?, last_update=? WHERE name=? AND domain=?",
                    [new_address, int(time.time()), new_name, domain])
            else:
                return "failed: supplied username / password not valid for domain"
        else:
            db.execute(
                "INSERT INTO record(name, domain, address, user_id, last_update) VALUES(?, ?, ?, ?, ?)",
                [new_name, domain, new_address, uid, int(time.time())])

        db.execute("UPDATE domain SET serial=serial+1 WHERE name=?", [domain, ])
        serial = list(db.execute("SELECT serial FROM domain WHERE name=?", [domain, ]))[0][0]

        # regenerate zone file
        (head, body) = file("/etc/bind/zones/"+domain, "r").read().split(";; start dynamic ;;")

        fp = file("/etc/bind/zones/"+domain, "w")
        fp.write(re.sub("\d+ ; Serial", str(serial) + " ; Serial", head) + ";; start dynamic ;;\n")
        for record in db.execute("SELECT name,address FROM record WHERE domain=? ORDER BY name", [domain, ]):
            fp.write("%-30s IN %-4s %s\n" % (record[0], get_type(record[1]), record[1]))
        fp.close()

        os.system("sudo /etc/init.d/bind9 reload")

        return "ok: "+new_name+"."+domain+" = "+new_address
    finally:
        db_conn.commit()
        db_conn.close()


def get_type(addr):
    if ":" in addr:
        return "AAAA"
    else:
        return "A"

def get_zone(hostname):
    return re.sub("master[46]\.", "", hostname)

def get_ip(remote):
    return re.sub("^::ffff:", "", remote)

def valid_name(name):
    return re.match("^[a-z0-9\-]+$", name)


if __name__ == "__main__":
    logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s %(levelname)-8s %(message)s',
            filename="../logs/app.log")
    smtp = logging.handlers.SMTPHandler(
            "localhost", "noreply@shishnet.org",
            ["shish+ddns@shishnet.org", ], "ddns error report")
    smtp.setLevel(logging.WARNING)
    logging.getLogger('').addHandler(smtp)

    app.run()
