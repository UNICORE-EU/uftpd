from struct import pack, unpack
from typing import List

from Connector import Connector
from Log import Logger

class PConnector(object):
    """
        Multi-stream connector that writes/reads multiple TCP (data)streams
        
        written to be compatible with the JPARSS library, which is
        Copyright (c) 2001 Southeastern Universities Research Association,
        Thomas Jefferson National Accelerator Facility
    """

    def __init__(self, connectors: List[Connector], LOG: Logger, key=None, algo: str="BLOWFISH", compress=False):
        self._connectors = connectors
        self._inputs = []
        self._outputs = []
        self.LOG = LOG
        self.encrypt = key is not None
        if self.encrypt:
            import CryptUtil
        for conn in connectors:
            if self.encrypt:
                cipher = CryptUtil.create_cipher(key, algo)
                self._outputs.append(CryptUtil.CryptWriter(conn, cipher))
                self._inputs.append(CryptUtil.DecryptReader(conn, cipher))
            else:
                self._outputs.append(conn.client.makefile("wb"))
                self._inputs.append(conn.client.makefile("rb"))
        self.seq = 0
        self.num_streams = len(self._connectors)
        if compress:
            import GzipConnector
            for i in range(0, self.num_streams):
                self._inputs[i] = GzipConnector.GzipReader(self._inputs[i])
                self._outputs[i] = GzipConnector.GzipWriter(self._outputs[i])

    def write(self, data):
        """ Write all the data to remote channel """
        _magic = 0xcebf
        size = len(data)
        chunk = int(len(data) / self.num_streams)
        i = 0
        for out in self._outputs:
            offset = i * chunk
            if i == self.num_streams - 1:
                chunk_len = size - i * chunk
            else:
                chunk_len = chunk
            self._write_block(pack(">HHIII", _magic, i, self.seq, size, chunk_len)
                             +data[offset:offset+chunk_len], out)
            i += 1
        self.seq += 1
        return len(data)

    def _write_block(self, data, _out):
        """ Write all the data to out """
        to_write = len(data)
        write_offset = 0
        while to_write > 0:
            written = _out.write(data[write_offset:])
            if written is None:
                written = 0
            write_offset += written
            to_write -= written
        _out.flush()

    def _read_block(self, length, _in):
        _chunks = []
        _have = 0
        while _have < length:
            want = min(length - _have, length)
            chunk = _in.read(want)
            if chunk == b'':
                break
            _chunks.append(chunk)
            _have = _have + len(chunk)
        return b''.join(_chunks)

    def read(self, length):
        """ Read data from remote channel """
        buffer = bytearray(length)
        _magic = 0xcebf
        for i in range(0, self.num_streams):
            src = self._inputs[i]
            header = self._read_block(16, src)
            if len(header)==0:
                # EOF
                return []
            (magic, pos, seq, size, chunk_len) = unpack(">HHIII", header)
            if pos!=i:
                raise Exception("I/O error reader %s (unexpected stream position: )" % (i,pos))
            if magic!=_magic:
                raise Exception("I/O error reader %s (magic number)" % i)
            if seq!=self.seq:
                raise Exception("I/O error reader %s (sequence number)" % i)
            chunk = int(size / self.num_streams)
            offset = pos * chunk
            buffer[offset:offset+chunk_len] = src.read(chunk_len)
        self.seq += 1
        return buffer[0:size]

    def close(self):
        for i in range(0, self.num_streams):
            try:
                self._connectors[i].close()
            except:
                pass
