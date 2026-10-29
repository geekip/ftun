#!/usr/bin/env python3
"""peer 命名空间里的假上游：DNS（.53/.54）、FRS HTTP（.80）、TCP 回显（.7:7000）和
读得很慢的槽（.7:7001，窗口常为零但有进展）和完全不读的槽（.7:7002）。行为由 control 目录里的文件切换，
命中次数写回 control 目录供测试读取。用法：fakes.py <control 目录> <FRS 文件>"""
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time

control = Path(sys.argv[1])
frs_bytes = Path(sys.argv[2]).read_bytes()
lock = threading.Lock()


def count(name):
    with lock:
        path = control / name
        value = int(path.read_text() or 0) if path.exists() else 0
        path.write_text(str(value + 1))


def mode(name, default='normal'):
    path = control / name
    return path.read_text().strip() if path.exists() else default


def question_end(packet):
    offset = 12
    while offset < len(packet) and packet[offset] != 0:
        offset += packet[offset] + 1
    return offset + 5


def dns(address, answer):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, 53))
    tag = address.rsplit('.', 1)[1]
    while True:
        query, peer = sock.recvfrom(4096)
        count(f'dns{tag}.queries')
        current = mode(f'dns{tag}.mode')
        if current == 'silent' or len(query) < 12:
            continue
        end = question_end(query)
        ident = query[:2]
        if current == 'badid':
            ident = bytes([query[0] ^ 0xFF, query[1]])
        if current == 'malformed':
            sock.sendto(ident + b'\x81\x80\x00\x01\x00\x01garbage', peer)
            continue
        header = ident + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
        # FRS 下载地址只能写主机名（控制通道总是经解析器）；夹具的 CN 集合含 192.0.2.0/24，所以假上游用 198.51.100.0/24（控制通道总是经解析器），固定解析到 .80。
        target = '198.51.100.80' if query[12:end].startswith(b'\x03frs\x03lab\x04test\x00') else answer
        record = b'\xc0\x0c' + struct.pack('!HHIH4s', 1, 1, 60, 4, socket.inet_aton(target))
        sock.sendto(header + query[12:end] + record, peer)


def http():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('198.51.100.80', 80))
    server.listen(16)
    while True:
        client, _ = server.accept()
        threading.Thread(target=http_client, args=(client,), daemon=True).start()


def http_client(client):
    try:
        client.settimeout(5)
        request = b''
        while b'\r\n\r\n' not in request:
            chunk = client.recv(4096)
            if not chunk:
                return
            request += chunk
        count('frs.hits')
        if mode('frs.mode') == 'down':
            return
        head = (b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n'
                b'Content-Length: ' + str(len(frs_bytes)).encode() + b'\r\nETag: "v1"\r\n'
                b'Connection: close\r\n\r\n')
        client.sendall(head + frs_bytes)
    except OSError:
        pass
    finally:
        client.close()


def tcp_server(port, handler):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if port in (7001, 7002):
        server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    server.bind(('198.51.100.7', port))
    server.listen(64)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handler, args=(client,), daemon=True).start()


def echo(client):
    count('echo.accepted')
    try:
        while True:
            data = client.recv(65536)
            if not data:
                break
            client.sendall(data)
    except OSError:
        pass
    finally:
        client.close()


def sink(client):
    # 接收缓冲区很小、读得很慢：对端窗口常常为零，但每秒都有数据被确认（有写入进展）。
    count('sink.accepted')
    try:
        while client.recv(512):
            time.sleep(1.0)
    except OSError:
        pass


def stalled(client):
    # 完全不读取：窗口收到零后不再有任何进展，但连接本身存活并应答探测。
    count('stalled.accepted')
    time.sleep(3600)


for target, args in ((dns, ('198.51.100.53', '203.0.113.5')), (dns, ('198.51.100.54', '203.0.113.6')),
                     (http, ()), (tcp_server, (7000, echo)), (tcp_server, (7001, sink)),
                     (tcp_server, (7002, stalled))):
    threading.Thread(target=target, args=args, daemon=True).start()
time.sleep(0.3)
(control / 'ready').write_text('1')
while True:
    time.sleep(3600)
