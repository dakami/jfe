# jfe
Jump Fast Encrypt

# Quick Demo
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
