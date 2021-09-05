import socket
import select    ## for non-blocking sockets
import ssl
import errno     ## for socket error codes
import certifi   ## pip install certifi
import array     ## sockets only accept byte-arrays
import sys


#
# NOTE: do not forget to allow "Less secure apps" in your gmail settings
#


EOM = "\r\n"
DOMAIN = "pop.gmail.com"
PORT = 995

STATE_CREATED   = 0
STATE_WAIT_STAT = 1
STATE_EXIT      = 2


def toMsg(strMsg):
    return array.array('b', [ord(c) for c in strMsg + EOM])


def openSslConnectionToServer(domain, port):
    # I want to use TLSv1.3
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1

    # pass to the trust storage of security certificates
    context.load_verify_locations(certifi.where(), capath=None, cadata=None)

    # create Internet NON-BLOCKING socket 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # connect to the server
    result = sock.connect((domain, port))
    print("connect result:", result)

    # wrap TCP socket into SSL wrapper
    sslSock = context.wrap_socket(sock, server_hostname=domain)

    # I only can make it non-blocking after SSL handshake
    sslSock.setblocking(False) 

    # print TLS info
    print(sslSock.cipher())

    return sslSock



class PopMessageParcer():
    def __init__(self):
        self.messages = []
        self.current = ""

    def addData(self, stream):
        stream = [chr(b) for b in stream]
        for c in stream:
            if c == '\r':
                pass
            elif c == '\n':
                self.messages.append(self.current)
                self.current = ""
            else:
                self.current += c

    def hasMessages(self):
        return 0 < len(self.messages)

    def getMessages(self):
        result = self.messages
        self.messages = []
        return result

     



def main():
    parser = PopMessageParcer()

    sslSock = openSslConnectionToServer(DOMAIN, PORT)
    sockets = [sslSock]

    state = STATE_CREATED

    # main loop to read messages and send commands    
    while state != STATE_EXIT:

        # wait for input from server
        to_read, to_write, with_error = select.select(sockets, sockets, sockets, 10)

        # read network buffer
        for sock in to_read:
            while True:
                # read socket until it's empty
                try:
                    # 16 is just to enforce multiple reading
                    buffer = sock.recv(16)
                    parser.addData(buffer)
                except ssl.SSLWantReadError as e:
                    if errno.ENOENT != e.args[0]:
                        print("Socket recv error:", e)
                        sys.exit(1)
                    else:
                        # socket is empty
                        break

            # work with server: login and get statistic, then disconnect
            if parser.hasMessages():
                for msg in parser.getMessages():
                    print(">>", msg)
                    if msg.startswith("+OK Gpop ready for requests"):
                        sock.send(toMsg("USER your-email@googlemail.com"))
                    elif msg.startswith("+OK send PASS"):
                        sock.send(toMsg("PASS your-password"))
                    elif msg.startswith("+OK Welcome."):
                        state = STATE_WAIT_STAT
                        sock.send(toMsg("STAT"))
                    elif msg.startswith("+OK"):
                        if state == STATE_WAIT_STAT:
                            print(">> closing socket")
                            sock.shutdown(socket.SHUT_RDWR)
                            sock.close()
                            state = STATE_EXIT
                            break

            
       


if __name__ == "__main__":
    main()



