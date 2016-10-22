# jfe
Jump to Full Encryption

# Quick Demo
    root@MacCyber:~/jfe# ./jfe --staging -h
    Usage:
    JFE (Jump to Full Encryption):  Full System Encryption Agent
    Dan Kaminsky, Chief Scientist, whiteops.com
    
    NOTE:  This is just a demonstration of a system-wide "bump in the wire"
    TLS implementation providing encryption on demand when requested by a
    client, using the new machine acquirable certicates freely available
    from Certbot/Let's Encrypt/CertBot.
    
    Options:
      -h, --help            show this help message and exit
      --clear               Clear cached certs/creds
      -s, --staging         Use Staging Server (Not As Rate Limited)
      -w WEBROOT, --webroot=WEBROOT
                            Location of webroot (/var/www/html)
      -c ACCOUNTCACHE, --cache=ACCOUNTCACHE
                            Location of cached credentials (/var/jfe)
      -v, --verbose         Verbose (false)
  
    root@Server:~/jfe# ./jfe.py --staging
    ...
    
    user@Client:~# curl -k http://163.jfe.example
    hello worl
    
    # Zero configuration, that server has TLS
    user@Client:~# curl -k https://163.jfe.example
    hello worl
    
    # ...as does every TCP server on this host
    user@Client:~# curl -k https://163.jfe.example:40000
    <!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
    
    <html>
    ...    

# HOWTO
It's actually mildly tricky to make all these pieces work together,
and I haven't entirely figured out how to get everything I want.

Here's implementation requirements right now.  Don't care about
implementation language -- it's a daemon.

1) Need to be able to setsockopt IP_TRANSPARENT onto the listening
socket, after listen() and before bind() (same at SO_REUSEADDR).

2) Need to be able to do a MSG_PEEK into the accept()'ed socket,
to see if TLS is being requested by the client.  Alternatively, need
to be able to upgrade a socket from TCP to TLS having already read
bytes from it, including the bytes from the CLIENT_HELLO.  It's already
a miracle when an ecosystem supports upgrading a connection already in
progress without already read bytes (as required by Deferred TLS / SMTP's
STARTTLS) so I'm doubtful, but depending on MSG_PEEK is of course
wrong and terrible and suboptimal.

3) Need to be able to change certificate based on the results of a
SNI callback.

4) Need to not block all other sessions in progress while this particular
session goes out and gets a cert.

There's all sorts of issues in the present implementation.  Probably the
biggest one is the client thinks it's talking to localhost, which of course
exposes localhost services.  I'm averse to nothing, including kernel hacking
and modules.  Performance on this threading implementation is also poor,
and the local HTTP server isn't working for reasons.  But heh!  Let's fix things.