#!/usr/bin/python
__doc__ = """
<html>
	<head>
		<title>TIny DYnamic DNS</title>
        <style>
INPUT {
    width: 100%%;
}
TD {
    vertical-align: top;
    padding: 16px;
}
        </style>
	</head>
	<body>

<table><tr><td colspan="6">

    <h1>TIny DYnamic DNS</h1>

    <h3>Example</h3>
    <pre>$ curl http://shish:mcpassword@master4.%(hostname)s/marigold
ok: marigold.clients.%(hostname)s = 81.171.46.249

$ curl http://shish:mcpassword@master6.%(hostname)s/marigold
ok: marigold.clients.%(hostname)s = 2002:51ab:2ef9::1

$ ping marigold.clients.%(hostname)s
PING marigold.clients.%(hostname)s (81.171.46.249) 56(84) bytes of data.
64 bytes from marigold.shishnet.org (81.171.46.249): icmp_seq=1 ttl=53 time=39.5 ms
64 bytes from marigold.shishnet.org (81.171.46.249): icmp_seq=2 ttl=53 time=55.0 ms
    </pre>

</td></tr><tr><td colspan="2" width="33%%">

    <h3>Register</h3>
    Email address is used for password resets and contacting you if there's anything
    suspicious. Feel free to leave it blank, but you won't get any support if I can't
    contact you, and your account may be deleted without warning :-P

    <form action="/register" method="POST">
        <br><input type="text" name="username" placeholder="Username" required="required" />
        <br><input type="password" name="password" placeholder="Password" required="required" />
        <br><input type="email" name="mailaddr" placeholder="Email address" />
        <br><input type="submit" value="Register" />
    </form>

</td><td colspan="2" width="33%%">

    <h3>Reset</h3>
    Enter username *or* a registered hostname (if using the hostname option, put just the
    hostname, eg "marigold", not "marigold.clients.%(hostname)s")

    <form action="/reset" method="POST">
        <br><input type="text" name="username" placeholder="Username" />
        <br><input type="text" name="hostname" placeholder="Hostname" />
        <br><input type="submit" value="Reset" />
    </form>

</td><td colspan="2">

    <h3>Update Account</h3>
    This is about as account-managementy as it gets. If you want to keep the email address
    or password unchanged, leave the field blank.

    <form action="/passwd" method="POST">
        <br><input type="text" name="username" placeholder="Username" required="required" />
        <br><input type="password" name="password_old" placeholder="Current Password" required="required" />
        <br><input type="email" name="mailaddr" placeholder="Email Address" />
        <br><input type="password" name="password_new1" placeholder="New Password" />
        <br><input type="password" name="password_new2" placeholder="Repeat New Password" />
        <br><input type="submit" value="Change" />
    </form>

</td></tr><tr><td colspan="3" width="50%%">

    <h3>Fine Print</h3>
    <ul>
        <li>Subdomains are added as used, first-come first-served
        <li>This is a free service run for my own use and entertainment. If you want
        some professional-level support / performance / reliability / etc, send me an
        email and we can work out payment :-)
    </ul>

</td><td colspan="3">

    <h3>Why?</h3>
    I wanted IPv6 compatible dynamic DNS for my
    <a href="http://en.wikipedia.org/wiki/Teredo_tunneling">teredo</a>-enabled
    laptop &amp; desktop; all the other dynamic dns providers were IPv4 only,
    non-free, or a pain to work with. It nearly counts as revision for my networking
    exam in a couple of weeks too \o/

    <p>-- Shish &lt;webmaster at shishnet.org&gt;

</td></tr></table>

	<body>
</html>
"""

# {{{ Database

import re
import os
import base64
import hashlib


def get_type(addr):
    if ":" in addr:
        return "AAAA"
    else:
        return "A"


from sqlalchemy import create_engine, func
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy import ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, backref

Session = sessionmaker()
Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    mailaddr = Column(String)
    created = Column(DateTime, nullable=False, default=func.now())
    reset_code = Column(String)
    reset_expire = Column(DateTime)

    records = relationship("Record")

    def __init__(self, username):
        self.username = username

    def set_password(self, password):
        self.password = bcrypt.hashpw(password, bcrypt.gensalt())
        self.reset_code = None
        self.reset_expire = None

    def check_password(self, password):
        return (bcrypt.hashpw(password, self.password) == self.password)

    def __repr__(self):
       return "User(%r, %r, %r)" % (self.username, self.fullname, self.password)


class Record(Base):
    __tablename__ = "records"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    type = Column(String, nullable=False)
    domain = Column(String, nullable=False)
    name = Column(String, nullable=False)
    value = Column(String, nullable=False)
    created = Column(DateTime, nullable=False, default=func.now())
    updated = Column(DateTime, nullable=False, default=func.now())

    user = relationship("User")

    def __repr__(self):
       return "Record(%r, %r, %r, %r)" % (self.name, self.domain, self.type, self.value)


def db_init():
    engine = create_engine('sqlite:///ddns.db', echo=False)
    Base.metadata.create_all(engine)
    Session.configure(bind=engine)

    session = Session()
    if not session.query(User).filter_by(username="system").first():
        u = User("system")
        u.password = "- no login -"
        session.add(u)
    session.commit()


def db_fetch(domain, name, type):
    # TODO: get our own IP address
    if name == "master4":
        return "91.121.120.226"
    if name == "master6":
        return "2001:0:53aa:64c:882:212a:a486:871d"
    session = Session()
    record = session.query(Record).filter_by(domain=domain, name=name, type=type).first()
    addr = record.value if record else None

    logging.info("Responding to request for %s.%s (%s) with %s" % (name, domain, type, addr))
    return addr

# }}}
# {{{ DNS Server

import socket

from dnslib import A, AAAA, CNAME, MX, RR, TXT
from dnslib import DNSHeader, DNSRecord, QTYPE


def dns_handler(s, peer, data):
    # parse request
    request = DNSRecord.parse(data)
    name, _, domain = str(request.q.qname).partition(".")

    # create response
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    # fill response
    if request.q.qtype == QTYPE.A or request.q.qtype == QTYPE['*']:
        ip = db_fetch(domain, name, "A")
        if ip:
            reply.add_answer(RR(request.q.qname, request.q.qtype, rdata=A(ip)))
    if request.q.qtype == QTYPE.AAAA or request.q.qtype == QTYPE['*']:
        ip = db_fetch(domain, name, "AAAA")
        if ip:
            ip = [ord(x) for x in socket.inet_pton(socket.AF_INET6, ip)]
            reply.add_answer(RR(request.q.qname, request.q.qtype, rdata=AAAA(ip)))

    # send response
    s.sendto(reply.pack(), peer)


def main_dns(args=[]):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 53))

    os.setgid(1000)
    os.setuid(1000)

    while True:
        try:
            data, peer = s.recvfrom(8192)
            dns_handler(s,peer,data)
        except Exception as e:
            logging.exception("Error responding to DNS request:")

# }}}
# {{{ Web Server 

import web
web.config.debug = True

import cgi
import cgitb; cgitb.enable()
import bcrypt
import uuid
import string
import random
from datetime import datetime, timedelta

update_app = web.application((
        '/(.*)', 'web_update',
    ), globals())
info_app = web.application((
        '/?', 'web_index',
        '/register', 'web_register',
        '/reset', 'web_reset',
        '/passwd', 'web_passwd',
    ), globals())

app = web.subdomain_application((
    "master[46]\..*", update_app,
    ".*", info_app,
))


class web_index:
    def GET(self):
        web.header('Vary', '*')

        return __doc__.strip() % {
            "hostname": web.ctx.env["HTTP_HOST"],
        }


class web_register:
    def POST(self):
        web.header('Content-Type', 'text/plain')
        web.header('Vary', '*')

        try:
            inp = web.input(username=None, password=None, mailaddr=None)
            username = inp.username
            password = inp.password
            mailaddr = inp.mailaddr

            if not username or not password:
                raise Exception("username and password must have data")

            session = Session()
            if session.query(User).filter_by(username=username).first():
                raise Exception("username taken")

            user = User(username)
            user.set_password(password)
            if mailaddr:
                user.mailaddr = mailaddr

            session.add(user)
            session.commit()
            logging.info("New user '%s <%s>'" % (username, mailaddr))
            return "ok: you may now add hosts :)\n"
        except Exception as e:
            return "error: %s\n" % str(e)


class web_reset:
    def POST(self):
        web.header('Content-Type', 'text/plain')
        web.header('Vary', '*')

        try:
            inp = web.input(username=None, hostname=None)

            session = Session()
            if inp.username:
                user = session.query(User).filter_by(username=inp.username).first()
            elif inp.hostname:
                record = session.query(Record).filter_by(name=inp.hostname, domain=web.ctx.env["HTTP_HOST"].replace("www.", "")).first()
                if not record:
                    raise Exception("invalid hostname")
                user = record.user
            else:
                raise Exception("need to specify username or hostname")

            if not user:
                raise Exception("invalid username")
            if not user.mailaddr:
                raise Exception("no email address for this account")

            user.reset_code = str(uuid.uuid1())
            user.reset_expire = datetime.now() + timedelta(days=1)
            session.commit()

            web.sendmail("TiDyDNS Support <shish+ddns@shishnet.org>", user.mailaddr, "Password Reset Code", """
Click here within 24 hours to get a new password:

http://www.tidydns.org/reset?username=%s&code=%s

    -- Shish
                """ % (user.username, user.reset_code))

            logging.info("Setting password reset token for %s to %s" % (user.username, user.reset_code))
            return "ok: password reset sent to that account's email address\n"
        except Exception as e:
            return "error: %s\n" % str(e)

    def GET(self):
        web.header('Content-Type', 'text/plain')
        web.header('Vary', '*')

        try:
            inp = web.input(username=None, code=None)

            session = Session()
            user = session.query(User).filter_by(username=inp.username).first()
            if not user:
                raise Exception("bad user")
            if not user.reset_code or user.reset_code != inp.code:
                raise Exception("bad code")
            if user.reset_expire < datetime.now():
                raise Exception("reset code expired")

            chars = string.ascii_letters
            newpass = "".join([random.choice(chars) for i in range(16)])
            user.set_password(newpass)
            session.commit()

            logging.info("Reset password for %s" % (inp.username, ))
            return "ok: your new password is %s\n" % newpass
        except Exception as e:
            return "error: %s\n" % str(e)


class web_passwd:
    def POST(self):
        web.header('Content-Type', 'text/plain')
        web.header('Vary', '*')

        try:
            inp = web.input(username=None, password_old=None, mailaddr=None, password_new1=None, password_new2=None)

            if not (inp.username and inp.password_old):
                raise Exception("missing data")

            session = Session()
            user = session.query(User).filter_by(username=inp.username).first()

            if not user:
                raise Exception("invalid username")
            if not user.check_password(inp.password_old):
                raise Exception("invalid password")

            old_mailaddr = user.mailaddr

            if inp.password_new1 or inp.password_new2:
                if inp.password_new1 != inp.password_new2:
                    raise Exception("new passwords don't match")
                user.set_password(inp.password_new1)
                logging.info("Set password for %s" % (user.username, ))

            if inp.mailaddr:
                user.mailaddr = mailaddr
                logging.info("Changed address for %s from %s to %s" % (user.username, old_mailaddr, user.mailaddr))

            session.commit()

            if old_mailaddr:
                web.sendmail("TiDyDNS Support <shish+ddns@shishnet.org>", old_mailaddr, "Details updated", """
Someone (you, I hope) has updated your account information.

If this was you, then all is fine; if it wasn't you, you have problems.

    -- Shish
                """)

            return "ok: password and / or email changed\n"
        except Exception as e:
            return "error: %s\n" % str(e)


class web_update:
    def GET(self, name):
        web.header('Content-Type', 'text/plain')
        web.header('Vary', '*')

        try:
            session = Session()

            if 'HTTP_AUTHORIZATION' not in web.ctx.env:
                raise Exception("no username / password specified")

            if not re.match("^[a-z0-9\-]+$", name):
                raise Exception("invalid subdomain")

            auth = web.ctx.env["HTTP_AUTHORIZATION"].partition(" ")[2]
            username, _, password = base64.b64decode(auth).partition(":")
            user = session.query(User).filter_by(username=username).first()
            if not user:
                raise Exception("invalid username")
            if not user.check_password(password):
                raise Exception("invalid username / password")

            domain = re.sub("master[46]\.", "clients.", web.ctx.env["HTTP_HOST"])
            value = re.sub("^::ffff:", "", web.ctx.env["REMOTE_ADDR"])
            type = get_type(value)

            # test for a previously-created record of any type with this name
            record = session.query(Record).filter_by(domain=domain, name=name).first()
            if record and not record.user == user:
                raise Exception("access denied")

            # create or update a record of this specific type
            record = session.query(Record).filter_by(domain=domain, name=name, type=type).first()
            if not record:
                record = Record(domain=domain, name=name, type=type, user=user)
                session.add(record)
            record.value = value
            record.updated = datetime.now()
            session.commit()

            logging.info("Updated %s.%s -> %s" % (name, domain, value))
            return "ok: %s.%s = %s\n" % (name, domain, value)
        except Exception as e:
            return "error: %s\n" % str(e)

# }}}
# {{{ Main

from threading import Thread

import logging
import logging.handlers

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

    logging.info("Starting DNS server thread")
    dnsd = Thread(target=main_dns)
    dnsd.daemon = True
    dnsd.start()

    logging.info("Initialising database")
    db_init()

    logging.info("Starting Web server thread")
    app.run()

# }}}
