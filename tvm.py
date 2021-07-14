import socket, ssl, uuid
from threading import Thread
import json, jwt
import time
from modbus_tk import modbus_tcp
import modbus_tk
import defines
import logging

logging.basicConfig(
    filename="./log/logfile.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# JWT from TTAS(SCADA Server)
jwtFromTTAS_SS = b''
# JWT from TTAS(TVM)
jwtFromTTAS_TVM = b''
# for prevent DoS attack
sequence_num = str(1)

dic = {}
dic = {
  'hostname': socket.gethostname(),
  'mac_addr': uuid.UUID(int = uuid.getnode()).hex[-12:],
  'ip': defines.SS_IP,
  'port': defines.SS_PORT,
  'dst_hostname': defines.SS_hostname,
  'dst_mac_addr': defines.SS_MAC_ADDR
}

# thread class
class ServerThread(Thread):

    def __init__(self, conn, addr, sock):
        Thread.__init__(self)
        self._conn = conn
        self._addr = addr
        self._sock = sock

    def run(self):
        global jwtFromTTAS_SS
        sleepTime = 1
        while True:
            try:
                messageFromTTASorSS = self._conn.recv(2048).decode("utf-8")
            except:
                logging.info("The connection has something wrong.")
                break

            # if SCADA server send "close", then close connection
            if messageFromTTASorSS == "close":
                self._conn.close()
                break

            # connect by TTAS
            if self._addr[0] == defines.TTAS_IP:
                jwtFromTTAS_SS = messageFromTTASorSS.encode("utf-8")
                self._conn.sendall("TVM got TTAS's Token.".encode("utf-8"))
                self._conn.close()
                break
            # connect by SCADA server
            elif self._addr[0] == defines.SS_IP:
                '''
                only SSL socket
                '''
                # messageFromTTASorSS = json.loads(messageFromTTASorSS)
                # master = modbus_tcp.TcpMaster(sensorDicFromSS["converter_ip"], sensorDicFromSS["converter_port"])
                # try:
                #     responseFromDevice = master.execute(
                #         slave=sensorDicFromSS["slave_id"]
                #         , function_code=sensorDicFromSS["function_code"]
                #         , starting_address=sensorDicFromSS["starting_address"]
                #         , quantity_of_x=sensorDicFromSS["quantity_of_x"])
                #     # print(responseFromDevice)

                # except modbus_tk.modbus.ModbusError as exc:
                #     print("%s- Code=%d", exc, exc.get_exception_code())
                #     self._conn.close()
                #     print(self._addr, "disconnect!")

                # except modbus_tcp.ModbusInvalidMbapError as exc:
                #     print(exc)
                #     self._conn.close()
                #     print(self._addr, "disconnect!")

                # self._conn.sendall(json.dumps(responseFromDevice).encode("utf-8"))
                # # self._conn.sendall(json.dumps((1234, 2234, 3234)).encode("utf-8"))
                # feadbackFromSS = self._conn.recv(1024).decode("utf-8")

                '''
                other
                '''
                splitDataFromScadaServer = messageFromTTASorSS.split("++")
                jwtFromSS = splitDataFromScadaServer[0].encode("utf-8")
                sensorDicFromSS = json.loads(splitDataFromScadaServer[1])
                # "JWT from TTAS" and "JWT from SCADA server" are the same
                if jwtFromTTAS_SS == jwtFromSS:
                    try:
                        decodedData = jwt.decode(jwtFromSS, jwt.decode(jwtFromSS, verify=False)["public_key"]
                            , issuer=defines.TTAS_IP, audience=self._addr[0], algorithm='ES256')
                        baseTime = decodedData['exp'] - decodedData['iat']
                        # check request frequency
                        # The usage frequency of the Token from SCADA Server is too high
                        if int(splitDataFromScadaServer[2]) / baseTime > 500:
                            logging.critical("The usage frequency of the Token from SCADA Server is too high, maybe it is a DoS attack.")
                            self._conn.sendall("too often".encode("utf-8"))
                            if sleepTime == 1:
                                self._conn.shutdown(self._sock.SHUT_RDWR)
                                self._conn.close()
                                break
                            time.sleep(sleepTime)
                            sleepTime *= 4
                        else:
                            self._conn.sendall("Legal".encode("utf-8"))
                            sleepTime = 1
                            """ TVM send request to device for request data or SCADA device,
                                TVM send data (with Token) obtained from device to SCADA server """
                            try:
                                master = modbus_tcp.TcpMaster(sensorDicFromSS["converter_ip"], sensorDicFromSS["converter_port"])
                                master.set_timeout(5.0)
                                responseFromDevice = master.execute(
                                    slave=sensorDicFromSS["slave_id"],
                                    function_code=sensorDicFromSS["function_code"],
                                    starting_address=sensorDicFromSS["starting_address"],
                                    quantity_of_x=sensorDicFromSS["quantity_of_x"]
                                )
                            except modbus_tk.modbus.ModbusError as exc:
                                logging.info(exc + ". Get device's data error.")
                                responseFromDevice = "error"
                            '''
                            TVM without Token
                            '''
                            # self._conn.sendall(json.dumps(responseFromDevice).encode("utf-8"))
                            # # self._conn.sendall(json.dumps((1234, 2234, 3234)).encode("utf-8"))
                            # feadbackFromSS = self._conn.recv(1024).decode("utf-8")

                            '''
                            TVM with Token
                            '''
                            global jwtFromTTAS_TVM, sequence_num
                            # verify jwt from TVM via signature and decode it via ECDSA's public key
                            while True:
                                try:
                                    decodedData_TVM = jwt.decode(jwtFromTTAS_TVM, jwt.decode(jwtFromTTAS_TVM
                                        , verify=False)["public_key"], issuer=defines.TTAS_IP
                                        , audience=defines.TVM_IP, algorithm='ES256')

                                    break
                                except jwt.InvalidSignatureError:
                                    logging.info("Token's signature from TTAS (apply from TVM) is invalid.")
                                    connectTTAS()
                                except jwt.DecodeError:
                                    logging.info("Token from TTAS (apply from TVM) is invalid.")
                                    connectTTAS()
                                except jwt.ExpiredSignatureError:
                                    logging.info("Token from TTAS (apply from TVM) hss expired.")
                                    connectTTAS()
                                except jwt.InvalidIssuerError:
                                    logging.info("Token's issuer from TTAS (apply from TVM) is invalid.")
                                    connectTTAS()
                                except jwt.InvalidAudienceError:
                                    logging.info("Token's audience from TTAS (apply from TVM) is invalid.")
                                    connectTTAS()

                            response = (jwtFromTTAS_TVM.decode("utf-8") + "++" + json.dumps(responseFromDevice) + "++" + sequence_num).encode("utf-8")
                            self._conn.sendall(response)
                            # add 1 after using it once
                            sequence_num = str(int(sequence_num) + 1)

                            # wait for feadback of SCADA server
                            feadbackFromSS = self._conn.recv(1024).decode("utf-8")

                            while True:

                                # Token from TVM is legal, close connection
                                if feadbackFromSS == "close":
                                    break
                                elif feadbackFromSS == "too often":
                                    self._conn.shutdown(self._sock.SHUT_RDWR)
                                    self._conn.close()
                                    break
                                # Token from TVM is invalid (include data from device is abnormal)
                                # resend verification information to TTAS
                                else:
                                    connectTTAS()
                                    response = (jwtFromTTAS_TVM.decode("utf-8") + "++" + json.dumps(responseFromDevice) + "++" + sequence_num).encode("utf-8")
                                    self._conn.sendall(response)
                                    # add 1 after using it once
                                    sequence_num += str(int(sequence_num) + 1)
                                    feadbackFromSS = self._conn.recv(1024).decode("utf-8")

                    except jwt.InvalidSignatureError:
                        logging.info("Token's signature from SCADA server is invalid.")
                        self._conn.sendall("Signature verification failed.".encode("utf-8"))
                    except jwt.DecodeError:
                        logging.info("Token from SCADA server can not be decoded.")
                        self._conn.sendall("Decode Error.".encode("utf-8"))
                    except jwt.ExpiredSignatureError:
                        logging.info("Token from SCADA server has expired.")
                        self._conn.sendall("Signature has expired.".encode("utf-8"))
                    except jwt.InvalidAudienceError:
                        logging.info("Token's audience from SCADA server is invalid.")
                        self._conn.sendall("Audience is error.".encode("utf-8"))
                    except jwt.InvalidIssuerError:
                        logging.info("Token's issuer from SCADA server is invalid.")
                        self._conn.sendall("Issue is error.".encode("utf-8"))
                    except jwt.InvalidIssuedAtError:
                        logging.info("Token's issue time from SCADA server is invalid.")
                        self._conn.sendall("The time of the Token was issued which is error.".encode("utf-8"))
                else:
                    logging.info("Token from SCADA server is invalid.")
                    self._conn.sendall("Token from SCADA server is illegal.".encode("utf-8"))



# connect TTAS and send data to TTAS
def connectTTAS():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_verify_locations("./key/certificate.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
    with context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as sock:
        try:
            sock.connect((defines.TTAS_IP, defines.TTAS_PORT))

            global dic
            sock.sendall(bytes(json.dumps(dic), encoding="utf-8"))

            messageFromTTAS = sock.recv(2048)
            global jwtFromTTAS_TVM, sequence_num
            jwtFromTTAS_TVM = messageFromTTAS
            sequence_num = str(1)

            sock.sendall("close".encode("utf-8"))
            sock.close()

        except socket.error:
            logging.info("Connect TTAS error.")

def main():


    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain("./key/certificate.pem", "./key/privkey.pem")
    context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        # avoid continuous port occupation
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((defines.TVM_IP, defines.TVM_PORT))
        sock.listen(50)

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    # multi-thread
                    newThread = ServerThread(conn, addr, socket)
                    newThread.start()

                except KeyboardInterrupt:
                    break

if __name__ == "__main__":
    main()
