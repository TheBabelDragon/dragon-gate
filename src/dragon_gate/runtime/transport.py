"""Framed TCP transport for the peer control protocol."""

from __future__ import annotations

import asyncio
from typing import Any

from dragon_gate.runtime.protocol import MAX_MESSAGE_BYTES, decode_frame, encode_message


class ProtocolError(Exception):
    pass


class FramedConnection:
    """Length-prefixed JSON message stream over a StreamReader/Writer pair."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        read_timeout: float = 15.0,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.read_timeout = read_timeout
        self.closed = False

    async def send(self, msg: dict[str, Any]) -> None:
        if self.closed:
            raise ProtocolError("connection closed")
        data = encode_message(msg)
        self.writer.write(data)
        await self.writer.drain()

    async def recv(self) -> dict[str, Any]:
        if self.closed:
            raise ProtocolError("connection closed")
        try:
            hdr = await asyncio.wait_for(self.reader.readexactly(4), self.read_timeout)
        except asyncio.IncompleteReadError as e:
            raise ProtocolError("connection closed") from e
        except TimeoutError as e:
            raise ProtocolError("read timeout") from e
        length = int.from_bytes(hdr, "big")
        if length <= 0 or length > MAX_MESSAGE_BYTES:
            raise ProtocolError(f"invalid frame length: {length}")
        try:
            body = await asyncio.wait_for(
                self.reader.readexactly(length), self.read_timeout
            )
        except asyncio.IncompleteReadError as e:
            raise ProtocolError("truncated frame") from e
        except TimeoutError as e:
            raise ProtocolError("read timeout") from e
        return decode_frame(body)

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    @property
    def peer_addr(self) -> tuple[str, int] | None:
        try:
            return self.writer.get_extra_info("peername")
        except Exception:
            return None


async def connect_tcp(
    host: str, port: int, *,
    timeout: float = 10.0,
    read_timeout: float = 15.0,
) -> FramedConnection:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )
    return FramedConnection(reader, writer, read_timeout=read_timeout)


async def start_server(
    host: str,
    port: int,
    handler,
    *,
    backlog: int = 32,
) -> asyncio.AbstractServer:
    """Bind a TCP server. host='' or '0.0.0.0' is explicit public exposure."""
    async def _client_cb(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        conn = FramedConnection(reader, writer)
        try:
            await handler(conn)
        finally:
            await conn.close()

    return await asyncio.start_server(_client_cb, host, port, backlog=backlog)
