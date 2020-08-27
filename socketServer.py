import socket, ssl
from threading import Thread 
import json
import jwt, hashlib
import time
from enum import Enum

# address enumerate
class AddrType(Enum):
    IP = "192.168.87.134"
    PORT = 8001
    TBASIP = "192.168.87.128"
    TBASPORT = 8001
    CPIP = "192.168.87.1"
    CPPORT = 8001

# temporary database
class TempAccount(Enum):
    account = "a"
    passwd = "48c8947f69c054a5caa934674ce8881d02bb18fb59d5a63eeaddff735b0e9801e87294783281ae49fc8287a0fd86779b27d7972d3e84f0fa0d826d7cb67dfefc"
    key = "456"

# JWT from TBAS
jwtFromTBAS = b''

# thread class
class ServerThread(Thread):

    def __init__(self, conn, addr):
        Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        
    def run(self):
        global jwtFromTBAS
        while True:
            dataFromTBASorCP = self.conn.recv(2048)
            print ("From", self.addr, ": " + dataFromTBASorCP.decode("utf-8"))
            
            # connect by TBAS
            if self.addr[0] == AddrType.TBASIP.value:
                jwtFromTBAS = dataFromTBASorCP
                self.conn.sendall("Pi got TBAS's Token.".encode("utf-8"))
                self.conn.close()
                print(self.addr, "disconnect!")
                break
            # connect by control program
            elif self.addr[0] == AddrType.CPIP.value:
                # "JWT from TBAS" and "JWT from control program" are the same
                if jwtFromTBAS == dataFromTBASorCP:
                    try:
                        decodedData = jwt.decode(dataFromTBASorCP, jwt.decode(dataFromTBASorCP, verify=False)["public_key"].encode("utf-8")
                            , audience=self.addr[0], algorithm='RS256')
                        print(decodedData)
                        self.conn.sendall("Legal".encode("utf-8"))

                        """ Pi send request to device for request data or control device,
                            Pi send data(with token) obtained from device to control program """
                        time.sleep(12)
                        self.conn.sendall(dataFromTBASorCP)

                        # wait for feadback of control program
                        dataFromCP = self.conn.recv(1024).decode("utf-8")
                        
                        while True:
                            
                            # Token from Pi is legal
                            if dataFromCP == "close":
                                print("Token from Pi is legal.")
                                self.conn.close()
                                print(self.addr, "disconnect!")
                                break
                            # Token from Pi is illegal, resend verification information to TBAS
                            else:
                                print("Token from Pi is illegal.")
                                connectTBAS()
                                self.conn.sendall(jwtFromTBAS)
                                dataFromCP = self.conn.recv(1024).decode("utf-8")

                        
                    except jwt.InvalidSignatureError:
                        print("Signature verification failed.")
                        self.conn.sendall("Signature verification failed.".encode("utf-8"))
                    except jwt.DecodeError:
                        print("Decode Error.")
                        self.conn.sendall("Decode Error.".encode("utf-8"))
                    except jwt.ExpiredSignatureError:
                        print("Signature has expired.")
                        self.conn.sendall("Signature has expired.".encode("utf-8"))
                    except jwt.InvalidAudienceError:
                        print("Audience is error.")
                        self.conn.sendall("Audience is error.".encode("utf-8"))
                    except jwt.InvalidIssuerError:
                        print("Issue is error.")
                        self.conn.sendall("Issue is error.".encode("utf-8"))
                    except jwt.InvalidIssuedAtError:
                        print("The time of the Token was issued which is error.")
                        self.conn.sendall("The time of the Token was issued which is error.".encode("utf-8"))
                else:
                    self.conn.sendall("Your Token is illegal.".encode("utf-8"))

                break
            # if control program send "close", then close connection
            if dataFromTBASorCP.decode("utf-8") == "close":
                self.conn.close()
                print(self.addr, "disconnect!")
                break

# connect TBAS and send data to TBAS
def connectTBAS():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as ssock:
        try:
            ssock.connect((AddrType.TBASIP.value, AddrType.TBASPORT.value))
            dic = {}
            dic["account"] = input("Please enter your account : ")
            dic["passwd"] = input("Please enter your password : ")
            # dic["account"] = "a"
            # dic["passwd"] = "123"
            dic["ip"] = AddrType.CPIP.value
            dic["port"] = AddrType.CPPORT.value

            ssock.sendall(bytes(json.dumps(dic), encoding="utf-8"))
            dataFromTBAS = ssock.recv(2048)
            global jwtFromTBAS
            jwtFromTBAS = dataFromTBAS

            ssock.sendall("close".encode("utf-8"))

        except socket.error:
            print ("Connect error")

def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # load private key and certificate file
    context.load_cert_chain("./certificate.pem", "./privkey.pem")
    # prohibit the use of TLSv1.0, TLgSv1.1, TLSv1.2 -> use TLSv1.3
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)

    # open, bind, listen socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((AddrType.IP.value, AddrType.PORT.value))
        sock.listen(5)
        print ("Server start at: %s:%s" %(AddrType.IP.value, AddrType.PORT.value))
        print ("Wait for connection...")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    # multi-thread
                    newThread = ServerThread(conn, addr)
                    newThread.start()
                    newThread.join()
                    #print("I'm freek")
                    
                except KeyboardInterrupt:
                    break

if __name__ == "__main__":
    main()