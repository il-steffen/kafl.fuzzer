# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Abstractions for kAFL Manager/Worker communicaton.
"""

import select

import logging
import msgpack
from multiprocessing.connection import Listener, Client

MSG_READY = 0
MSG_IMPORT = 1
MSG_IMPORT_SYX = 11
MSG_RUN_NODE = 2
MSG_NODE_DONE = 3
MSG_NODE_ABORT = 6
MSG_NEW_INPUT = 4
MSG_BUSY = 5
MSG_SYM_WAIT = 7 # qemu-syx is ready and waiting for a request
MSG_SYM_NEW = 8 # qemu-kvm wants to send a symbolic execution request
MSG_SYM_REQUEST = 9 # send a symbolic execution request to qemu-syx
MSG_SYM_RESULT = 10 # send a symbolic result
MSG_PRINT = 12 # print a message from the manager side

KAFL_NAMED_SOCKET = '/kafl_socket'

class ServerConnection:
    def __init__(self, config):
        Listener.fileno = lambda self: self._listener._socket.fileno()
        self.address = config.work_dir + KAFL_NAMED_SOCKET
        self.listener = Listener(self.address, 'AF_UNIX', backlog=1000)
        self.clients = [self.listener]
        self.clients_seen = 0
        self.logger = logging.getLogger(__name__)

    def wait(self, timeout=None):
        results = []
        r, w, e = select.select(self.clients, (), (), timeout)
        for sock_ready in r:
            if sock_ready == self.listener:
                c = self.listener.accept()
                self.clients.append(c)
                self.clients_seen += 1
            else:
                try:
                    msg = sock_ready.recv_bytes()
                    msg = msgpack.unpackb(msg, strict_map_key=False)
                    results.append((sock_ready, msg))
                except (EOFError, IOError):
                    sock_ready.close()
                    self.clients.remove(sock_ready)
                    self.logger.info("Worker disconnected (remaining %d/%d)." % (len(self.clients)-1, self.clients_seen))
                    if len(self.clients) == 1:
                        raise SystemExit("All Workers exited.")
        return results

    def send_import(self, client, task_data):
        client.send_bytes(msgpack.packb({"type": MSG_IMPORT, "task": task_data}))
    
    def send_import_syx(self, client, task_data):
        client.send_bytes(msgpack.packb({"type": MSG_IMPORT_SYX, "task": task_data}))

    def send_node(self, client, task_data):
        client.send_bytes(msgpack.packb({"type": MSG_RUN_NODE, "task": task_data}))

    def send_busy(self, client):
        client.send_bytes(msgpack.packb({"type": MSG_BUSY}))

    def send_sym_request(self, client, sym_request):
        client.send_bytes(msgpack.packb(
            {"type": MSG_SYM_REQUEST, "request": sym_request}))

class ClientConnection:
    def __init__(self, pid, config, is_symbolic):
        self.pid = pid
        self.address = config.work_dir + KAFL_NAMED_SOCKET
        self.sock = self.connect()
        if is_symbolic:
            self.send_sym_wait()
        else:
            self.send_ready()

    def connect(self):
        sock = Client(self.address, 'AF_UNIX')
        return sock

    def recv(self):
        data = self.sock.recv_bytes()
        return msgpack.unpackb(data, strict_map_key=False)

    def send_ready(self):
        self.sock.send_bytes(msgpack.packb({"type": MSG_READY, "worker_id": self.pid}))

    def send_new_input(self, data, bitmap, info):
        self.sock.send_bytes(msgpack.packb(
            {"type": MSG_NEW_INPUT, "input": {"payload": data, "bitmap": bitmap, "info": info}}))

    def send_node_done(self, node_id, results, new_payload):
        self.sock.send_bytes(msgpack.packb(
            {"type": MSG_NODE_DONE, "node_id": node_id, "results": results, "new_payload": new_payload}))

    def send_node_abort(self, node_id, results):
        self.sock.send_bytes(msgpack.packb(
            {"type": MSG_NODE_ABORT, "node_id": node_id, "results": results}))

    def send_print(self, msg):
        self.sock.send_bytes(msgpack.packb(
            {"type": MSG_PRINT, "msg": msg}))

    def send_sym_new(self, sym_requests):
        self.sock.send_bytes(msgpack.packb(
            {"type": MSG_SYM_NEW, "requests": list(map(lambda req: req.pack(), sym_requests))}
        ))

    def send_sym_wait(self):
        self.sock.send_bytes(msgpack.packb(
            {"type": MSG_SYM_WAIT}
        ))

    def send_sym_result(self, results):
        self.sock.send_bytes(msgpack.packb(
            {"type": MSG_SYM_RESULT, "results": results}
        ))

