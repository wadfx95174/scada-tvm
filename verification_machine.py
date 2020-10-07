import socket, ssl, uuid
from threading import Thread 
import json
import jwt, hashlib
import time
from modbus_tk import modbus_tcp
import modbus_tk.defines as cst
import modbus_tk
import addr_defines

# JWT from TTAS(CP)
jwtFromTTAS_CP = b''
# JWT from TTAS(TVM)
jwtFromTTAS_TVM = b''

dic = {}
dic = {
  'hostname': socket.gethostname(),
  'mac_addr': uuid.UUID(int = uuid.getnode()).hex[-12:],
  'ip': addr_defines.CP_IP,
  'port': addr_defines.CP_PORT
}

# thread class
class ServerThread(Thread):

    def __init__(self, conn, addr):
        Thread.__init__(self)
        self._conn = conn
        self._addr = addr
        
    def run(self):
        global jwtFromTTAS_CP
        while True:
            dataFromTTASorCP = self._conn.recv(2048)
            print ("From", self._addr, ": " + dataFromTTASorCP.decode("utf-8"))
            
            # connect by TTAS
            if self._addr[0] == addr_defines.TTAS_IP:
                jwtFromTTAS_CP = dataFromTTASorCP
                self._conn.sendall("TVM got TTAS's Token.".encode("utf-8"))
                self._conn.close()
                print(self._addr, "disconnect!")
                break
            # connect by control program
            elif self._addr[0] == addr_defines.CP_IP:
                
                s = dataFromTTASorCP.decode("utf-8").split("+++++")
                # print(dataFromTTASorCP.decode("utf-8"))
                jwtFromCP = s[0].encode("utf-8")
                sensorDicFromCP = json.loads(s[1])

                # "JWT from TTAS" and "JWT from control program" are the same
                if jwtFromTTAS_CP == jwtFromCP:
                    try:
                        decodedData = jwt.decode(jwtFromCP, jwt.decode(jwtFromCP, verify=False)["public_key"].encode("utf-8")
                            , issuer=addr_defines.TTAS_IP, audience=self._addr[0], algorithm='RS256')
                        # print(decodedData)
                        self._conn.sendall("Legal".encode("utf-8"))

                        """ TVM send request to device for request data or control device,
                            TVM send data(with token) obtained from device to control program """
                        # master = modbus_tcp.TcpMaster(sensorDicFromCP["converter_ip"], sensorDicFromCP["converter_port"])
                        # try:
                        #     responseFromDevice = master.execute(
                        #         slave=sensorDicFromCP["slave_id"]
                        #         , function_code=sensorDicFromCP["function_code"]
                        #         , starting_address=sensorDicFromCP["starting_address"]
                        #         , quantity_of_x=sensorDicFromCP["quantity_of_x"])
                        #     print(responseFromDevice)

                        # except modbus_tk.modbus.ModbusError as exc:
                        #     print("%s- Code=%d", exc, exc.get_exception_code())
                        #     self._conn.close()
                        #     print(self._addr, "disconnect!")

                        # except modbus_tcp.ModbusInvalidMbapError as exc:
                        #     print(exc)
                        #     self._conn.close()
                        #     print(self._addr, "disconnect!")

                        global jwtFromTTAS_TVM
                        # verify jwt from TVM via signature and decode it via rsa's public key
                        while True:
                            try:
                                decodedData = jwt.decode(jwtFromTTAS_TVM, jwt.decode(jwtFromTTAS_TVM
                                    , verify=False)["public_key"].encode("utf-8"), issuer=addr_defines.TTAS_IP
                                    , audience=addr_defines.TVM_IP, algorithm='RS256')
                                break
                            except jwt.InvalidSignatureError:
                                connectTTAS()
                            except jwt.DecodeError:
                                connectTTAS()
                            except jwt.ExpiredSignatureError:
                                connectTTAS()
                            except jwt.InvalidIssuerError:
                                connectTTAS()
                            except jwt.InvalidAudienceError:
                                connectTTAS()
                        
                        # response = (jwtFromTTAS_TVM.decode("utf-8") + "+++++" + json.dumps(responseFromDevice)).encode("utf-8")
                        response = (jwtFromTTAS_TVM.decode("utf-8") + "+++++" + json.dumps((1234, 2234, 3234))).encode("utf-8")
                        # print("response", response)
                        # time.sleep(12)
                        self._conn.sendall(response)

                        # wait for feadback of control program
                        feadbackFromCP = self._conn.recv(1024).decode("utf-8")
                        
                        while True:
                            
                            # Token from TVM is legal
                            if feadbackFromCP == "close":
                                print("Token from TVM is legal.")
                                # self._conn.close()
                                # print(self._addr, "disconnect!")
                                break

                            # Token from TVM is illegal, resend verification information to TTAS
                            else:
                                print(feadbackFromCP)
                                connectTTAS()
                                # response = (jwtFromTTAS_TVM.decode("utf-8") + "+++++" + json.dumps(responseFromDevice)).encode("utf-8")
                                response = (jwtFromTTAS_TVM.decode("utf-8") + "+++++" + json.dumps((1234, 2234, 3234))).encode("utf-8")
                                self._conn.sendall(response)
                                feadbackFromCP = self._conn.recv(1024).decode("utf-8")

                    except jwt.InvalidSignatureError:
                        print("Signature verification failed.")
                        self._conn.sendall("Signature verification failed.".encode("utf-8"))
                    except jwt.DecodeError:
                        print("Decode Error.")
                        self._conn.sendall("Decode Error.".encode("utf-8"))
                    except jwt.ExpiredSignatureError:
                        print("Signature has expired.")
                        self._conn.sendall("Signature has expired.".encode("utf-8"))
                    except jwt.InvalidAudienceError:
                        print("Audience is error.")
                        self._conn.sendall("Audience is error.".encode("utf-8"))
                    except jwt.InvalidIssuerError:
                        print("Issue is error.")
                        self._conn.sendall("Issue is error.".encode("utf-8"))
                    except jwt.InvalidIssuedAtError:
                        print("The time of the Token was issued which is error.")
                        self._conn.sendall("The time of the Token was issued which is error.".encode("utf-8"))
                else:
                    self._conn.sendall("Token from control program is illegal.".encode("utf-8"))

            # if control program send "close", then close connection
            if dataFromTTASorCP.decode("utf-8") == "close":
                self._conn.close()
                print(self._addr, "disconnect!")
                break

# connect TTAS and send data to TTAS
def connectTTAS():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.connect((addr_defines.TTAS_IP, addr_defines.TTAS_PORT))

            global dic
            sock.sendall(bytes(json.dumps(dic), encoding="utf-8"))

            dataFromTTAS = sock.recv(2048)
            global jwtFromTTAS_TVM
            jwtFromTTAS_TVM = dataFromTTAS

            sock.sendall("close".encode("utf-8"))
            sock.close()

        except socket.error:
            print ("Connect error")

def main():

    # connectTTAS()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # load private key and certificate file
    context.load_cert_chain("./key/certificate.pem", "./key/privkey.pem")
    # prohibit the use of TLSv1.0, TLgSv1.1, TLSv1.2 -> use TLSv1.3
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)

    # open, bind, listen socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        # avoid continuous port occupation
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr_defines.TVM_IP, addr_defines.TVM_PORT))
        sock.listen(5)
        print ("Server start at: %s:%s" %(addr_defines.TVM_IP, addr_defines.TVM_PORT))
        print ("Wait for connection...")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    # multi-thread
                    newThread = ServerThread(conn, addr)
                    newThread.start()
                    # newThread.join()
                    
                except KeyboardInterrupt:
                    break

if __name__ == "__main__":
    main()