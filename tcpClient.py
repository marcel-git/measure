import socket
import time

server_address=('134.96.225.80',8080)

with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
    sock.setsockopt(socket.SOL_SOCKET, 25, b'eno1')

    #sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('134.96.225.79',54321))
    sock.connect(server_address)

    data = "keep alive"
    while 1:
        #print("hi")
        sock.send(data.encode())
        #resp = sock.recv(1024)
        #print(f"Response: {resp}")
        #if not resp:
        #    break
        time.sleep(20)

