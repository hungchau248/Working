#
import socket
import thread


host = ''
port = 55679

def DataChannel(csock):
    csock.recv(1024)

def Server():
    while 1:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        while 1:
            (csock, caddr) = sock.accept()
            ComputerName = csock.recv(1024)
            WindowsVersion = csock.recv(1024)
            print "Computer: {}".format(ComputerName)
            print "Windows Version: {}".format(WindowsVersion)

            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.bind(('localhost', 0))
            uport = sock2.getsockname()[1]
            csock.send(str(uport) + "\n")

            #thread.start_new_thread(DataChannel, (csock,))

if __name__ == "__main__":
    Server()
