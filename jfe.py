#!/usr/bin/env python

import socket
import threading
import binascii
import ssl
import sys
import os
from free_tls_certificates import client as certbotClient
import re
from requests import get
import time
import optparse
import atexit
import os
import signal
import glob
import atexit
from SimpleHTTPServer import SimpleHTTPRequestHandler
from BaseHTTPServer import HTTPServer

def flush_mangle_table():
    os.system("iptables -F -t mangle")

atexit.register(flush_mangle_table)

def logger(msg):
    if opts.verbose: 
        print(msg)

challenges = {}
class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_IP, 19, 1) #ORDINALS!  Actually IP_TRANSPARENT
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            try: 
                client, address = self.sock.accept()
            except:
                sys.exit(1)
            try: threading.Thread(target = self.proxyConnection, args = (client,address)).start()
            except (KeyboardInterrupt, SystemExit):
                sys.exit(1)


    def proxyConnection(self, client, address):
        (host, port) = client.getsockname()

        sniff = client.recv(128, socket.MSG_PEEK).split("\n")[0]
        if sniff.find(".well-known/acme-challenge")>-1:
            port = 80
        if(port == 443): 
            port = 80
        sniff = binascii.hexlify(sniff)

        if(sniff[0:4]=="1603"): #XXX need better SSL sniff
            ctx=ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
            if not os.path.isfile(opts.accountcache + "/selfstub.cer"):
                cert=certbotClient.issue_certificate(
                    ["localhost"],
                    opts.accountcache,
                    logger=logger,
                    self_signed=True
                )
                open(opts.accountcache + "/selfstub.cer", "wb").write(cert["cert"] + '\n'.join(cert["chain"]) + cert["private_key"] + "\n")

            ctx.load_cert_chain(certfile=opts.accountcache + "/selfstub.cer")
            def on_sni(sslSocket,serverName,ctx):
                if not serverName: 
                    return None
                if not re.match("^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$", serverName): return None #could error
                try:
                    remote = get('https://api.ipify.org').text  #NOT XXX -- This is apparently a stable IP discovery endpoint
                    dns    = socket.gethostbyname(serverName)   #    XXX -- This needs to check all A records, at least
                    if opts.verbose: 
                        print remote, dns
                    if remote != dns:
                        return None
                except:
                    return None
                certFile = opts.accountcache + "/" + serverName + ".cer"
                if not os.path.isfile(certFile): # XXX need to check for expiry
                    cert=self.getCert(serverName, certFile)
                    open(certFile, "wb").write(cert["cert"] + '\n'.join(cert["chain"]) + cert["private_key"] + "\n")
                newctx=ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
                newctx.load_cert_chain(certfile=certFile)
                sslSocket.context = newctx
                return None
            ctx.set_servername_callback(on_sni)
            try: 
                client = ctx.wrap_socket(client, server_side=True,suppress_ragged_eofs=True)
            except Exception as e:
                print e.message
                pass
        
        forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # XXX How to make the connection appear to come from its original source?
        try: forward.connect(("127.0.0.1", port))
        except:
            if(opts.verbose):
                print "Connection to port " + str(port) + "rejected"
            return

        client.setblocking(1)
        client.settimeout(999)
        forward.setblocking(1)
        forward.settimeout(999)
        threading.Thread(target = self.toForward, args = (client, address, forward)).start()
        threading.Thread(target = self.toClient,  args = (client, address, forward)).start()
        
    def getCert(self, serverName, certFile):
        tos_url = None
        if os.path.isfile(opts.accountcache + "/tos_url.txt"):
            tos_url = open(opts.accountcache + "/tos_url.txt", "r").read()
        try:
            acme = "https://acme-v01.api.letsencrypt.org/directory"
            if(opts.staging):
                acme="https://acme-staging.api.letsencrypt.org/directory"
            cert=certbotClient.issue_certificate(
                [serverName],
                opts.accountcache,
                agree_to_tos_url=tos_url,
                certificate_file=certFile,
                acme_server=acme,
                logger=logger
            )
            return cert
        except certbotClient.NeedToAgreeToTOS as e:
            tos_url = e.url
            open(opts.accountcache + "/tos_url.txt", "w").write(tos_url)
        except certbotClient.NeedToTakeAction as e:
            for action in e.actions:
                if isinstance(action, certbotClient.NeedToInstallFile):
                    f = open(opts.webroot + "/.well-known/acme-challenge/" + action.url.split("/")[-1], "w") # XXX exploitable
                    f.write(action.contents)
                    challenges[action.url.split("/")[-1]] = action.contents
                    f.close()
        except certbotClient.WaitABit as e:
            import datetime
            print ("Try again in %s." % (e.until_when - datetime.datetime.now()))                
        except:
            raise
        return self.getCert(serverName, certFile)
        
    def nuke(self, client, forward):
        try: 
            client.shutdown()
        except:
            pass
        try:
            forward.shutdown()
        except:
            pass
        
    def toForward(self, client, address, forward):
        while 1:
            try: 
                data = client.recv(1024)
                forward.send(data)
            except Exception as e:
                print e
                time.sleep(0.01)
                self.nuke(client, forward)
                return

    def toClient(self, client, address, forward):
        while 1:
            try: 
                data = forward.recv(1024)
                client.send(data)
            except Exception as e:
                print e
                time.sleep(0.01)
                self.nuke(client, forward)
                return

def apply_firewall():
    s = """
#!/bin/sh
iptables -F
iptables -F -t mangle
iptables -t mangle -N DIVERT
iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
iptables -t mangle -A DIVERT -j MARK --set-mark 1
iptables -t mangle -A DIVERT -j ACCEPT
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
iptables -t mangle -A PREROUTING  -p tcp --dport 23:65535 ! -d 127.0.0.1 -j TPROXY \
 --tproxy-mark 0x1/0x1 --on-port 1
iptables -L -t mangle
"""
    os.system(s)
   
opts = None
remainder = None

class RequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.protocol_version = 'HTTP/1.0'
        if(self.path[-1]=="/"): 
            self.path="/noindex"
        if True: #os.path.isfile(file):
            print "y"
            self.send_response(200)
            data = "123"
            #data = open(opts.webroot + self.path, "rb").read()
            self.end_headers()
            self.wfile.write(data)
        else:
            print "n"
            self.send_response(404)
            self.end_headers()



if __name__ == "__main__":
    usage ="""
JFE (Jump to Full Encryption):  Full System Encryption Agent
Dan Kaminsky, Chief Scientist, whiteops.com

NOTE:  This is just a demonstration of a system-wide "bump in the wire"
TLS implementation providing encryption on demand when requested by a
client, using the new machine acquirable certicates freely available
from Certbot/Let's Encrypt/CertBot."""

    parser = optparse.OptionParser(usage=usage)
#    parser.add_option("-D", "--daemon", dest="daemonize", default=False, action="store_true", help="Run as Background Daemon")
    parser.add_option("", "--clear", dest="clearcache", default=False, action="store_true", help="Clear cached certs/creds")
    parser.add_option("-s", "--staging", dest="staging", default=False, action="store_true", help="Use Staging Server (Not As Rate Limited)")
    parser.add_option("-w", "--webroot", dest="webroot", default="/var/www/html", help="Location of webroot (/var/www/html)")
    parser.add_option("-c", "--cache", dest="accountcache", default="/var/jfe", help="Location of cached credentials (/var/jfe)")
    parser.add_option("-v", "--verbose", dest="verbose", default=False, action="store_true", help="Verbose (false)")
    

    opts, remainder = parser.parse_args(sys.argv)
    print opts, remainder
    apply_firewall()
    if(opts.clearcache):
        for f in glob.glob(opts.accountcache + "/*"):
            os.remove(f)


    server = HTTPServer(("127.0.0.1", 2), RequestHandler)
    thread = threading.Thread(target = server.serve_forever)
    thread.daemon = True
    thread.start()
    try: 
        print "ummm"
        ThreadedServer('',1).listen()
    except:
        flush_mangle_table()
        os._exit(1)