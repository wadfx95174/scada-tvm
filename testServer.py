import socket, time, ssl
HOST = "192.168.87.134"
PORT = 8001

context = ssl.SSLContext(ssl.PROTOCOL_TLS)
# load private key and certificate file
context.load_cert_chain("./key/certificate.pem", "./key/privkey.pem")
# prohibit the use of TLSv1.0, TLSv1.1, TLSv1.2 -> use TLSv1.3
context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)

# open, bind, listen socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print ("Server start at: %s:%s" %(HOST, PORT))
    print ("Wait for connection...")

    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            try:
                conn, addr = ssock.accept()
                # multi-thread
                # newThread = ClientThread(conn, addr)
                # newThread.start()
            except KeyboardInterrupt:
                break