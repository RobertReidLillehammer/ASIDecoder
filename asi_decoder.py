"""
asi_decoder.py — Pure-Python decoder for ".ASI" GPS data files (AdMos and Protern).

Replicates asiDecoder.exe for the packets the analysis pipeline needs, so ASI
files can be read directly inside the video-analyzer software without shelling
out to the Windows executable:

  * AdMos  ("AdMos" device)  — packet 9, the u-blox UBX NAV-PVT message (10 Hz).
  * Protern ("PROSK" device) — packet 4 (sparse absolute keyframes) + packet 15
    (10 Hz stream of position deltas + ground speed), reconstructed into a 10 Hz
    absolute track by protern_track().

File format (reverse-engineered, validated byte-for-byte against the .exe output):

  Header (offset 0):
    "ASI\0" magic, version/cipher bytes, "ASI V2", author block, then a
    self-describing SCHEMA TABLE. Each schema entry is:
        [type_id:u8][field_count:u8] followed by field_count x [b0:u8][b1:u8]
    Field encoding:
        b0 == 0x00 : scalar. b1 is a SIGNED int8: +8/+16/+32 = unsigned width in
                     bits, -8/-16/-32 (0xF8/0xF0/0xE0) = signed width in bits.
        b0 == 0x07 : uint8 array of (b1) bytes
        other b0   : variable-length (string) — only used by the one-time
                     metadata packets at the start of the body.
    The schema ids are sequential (1,2,3,...); the table ends when the
    sequence breaks. The data section begins immediately after.

  Body: a stream of records, each   [tag:u8][payload].
    The packet id is the HIGH nibble of the tag:  packet_id = tag >> 4
    (the low nibble is a rolling counter). The payload size for each id comes
    from the schema. The stream ends with zero padding (tag 0x00).

  Both devices write the SAME schema table; they differ in which packets they
  emit. The device is named in the first packet-1 metadata record.

Packet 9 (NAV-PVT) has 32 little-endian fields; see PKT9_FIELDS below.
Packet 4 / 15 (Protern) fields: see PKT4_FIELDS / PKT15_FIELDS.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, NamedTuple

MAGIC = b"ASI\x00"
PKT9 = 9        # AdMos: u-blox NAV-PVT
PKT4 = 4        # Protern: absolute position keyframe
PKT15 = 15      # Protern: 10 Hz delta / speed stream

DEVICE_ADMOS = "AdMos"
DEVICE_PROTERN = "PROSK"

# Human-readable names + scale factors for the 32 NAV-PVT fields, in order.
# These mirror the u-blox UBX-NAV-PVT layout the AdMos receiver emits.
PKT9_FIELDS = [
    "iTOW", "year", "month", "day", "hour", "minute", "second",
    "valid", "tAcc", "nano", "fixType", "flags", "numSV", "reserved1",
    "lon", "lat", "height", "hMSL", "hAcc", "vAcc",
    "velN", "velE", "velD", "gSpeed", "headMot", "sAcc", "headAcc",
    "pDOP", "flags3", "field30", "field31", "field32",
]

# Protern packet 4 — one absolute fix per keyframe (irregular, ~every 3..800 s).
#   fixType 0..3 (u-blox convention: 3 = 3D fix); 2-digit year; ms = sub-second;
#   lat/lon in 1e-7 deg; alt in mm; timestamp = device uptime in 1/4000 s ticks
#   (the same 4 kHz clock as the AdMos "Timestamp" field).
PKT4_FIELDS = ["fixType", "yy", "month", "day", "hour", "minute", "second",
               "ms", "reserved", "lat", "lon", "alt", "timestamp"]

# Protern packet 15 — one record every 0.1 s.
#   marker  : -1 on the record that coincides with a packet-4 keyframe, else 0
#   imu0..3 : not decoded (likely body-frame IMU axes; not needed here)
#   gSpeed  : ground speed, mm/s
#   dN,dE,dD: displacement since the previous record, North/East/Down, 1e-4 m
PKT15_FIELDS = ["marker", "imu0", "imu1", "imu2", "imu3", "gSpeed", "dN", "dE", "dD"]

PKT4_SIZE = 29
PKT15_SIZE = 23
PKT9_SIZE = 92

# protern_track(): still anchor a segment to its next keyframe when it is short
# by at most this many 10 Hz records (dropped samples); beyond that the logger
# paused and the deltas can't bridge the pause.
CLOSURE_MAX_MISSING = 3


class Schema(NamedTuple):
    field_codes: list  # list of (b0, b1)
    fmt: str | None    # struct format if fully scalar, else None
    size: int | None   # payload byte size if fixed, else None


def _parse_schema_table(buf: bytes, start: int = 18) -> tuple[dict[int, Schema], int]:
    """Return ({type_id: Schema}, data_section_offset)."""
    off = start
    prev = 0
    schemas: dict[int, Schema] = {}
    n = len(buf)
    while off + 2 <= n:
        tid, cnt = buf[off], buf[off + 1]
        if tid != prev + 1:  # ids are sequential; sequence break => table done
            break
        codes = [(buf[off + 2 + 2 * i], buf[off + 3 + 2 * i]) for i in range(cnt)]
        fmt: str | None = "<"
        size: int | None = 0
        for b0, b1 in codes:
            if b0 == 0x00:
                w = b1 - 256 if b1 >= 128 else b1     # signed int8: <0 => signed type
                bits = abs(w)
                if bits not in (8, 16, 32):
                    fmt, size = None, None
                    break
                c = {8: "b", 16: "h", 32: "i"}[bits]
                if fmt is not None:
                    fmt += c if w < 0 else c.upper()
                size += bits // 8
            elif b0 == 0x07:  # uint8[b1]
                fmt = None
                size = (size + b1) if size is not None else None
            else:  # variable length (string) — not needed for the streaming body
                fmt, size = None, None
                break
        schemas[tid] = Schema(codes, fmt, size)
        prev = tid
        off += 2 + cnt * 2
    return schemas, off


@dataclass
class AsiFile:
    schemas: dict[int, Schema]
    data_offset: int
    _buf: bytes

    @classmethod
    def open(cls, path: str) -> "AsiFile":
        buf = open(path, "rb").read()
        if buf[:4] != MAGIC:
            raise ValueError(f"{path}: not an ASI file (bad magic {buf[:4]!r})")
        schemas, data_off = _parse_schema_table(buf)
        return cls(schemas, data_off, buf)

    # ------------------------------------------------------------------ device
    def device_name(self) -> str | None:
        """'AdMos' or 'PROSK' (Protern), read from the first packet-1 metadata
        record; None if neither is found."""
        sch = self.schemas.get(1)
        span = 1 + (sch.size if sch and sch.size else 64)
        head = self._buf[self.data_offset:self.data_offset + span + 8]
        for name in (DEVICE_ADMOS, DEVICE_PROTERN):
            if name.encode("ascii") in head:
                return name
        return None

    @property
    def is_protern(self) -> bool:
        return self.device_name() == DEVICE_PROTERN

    # ------------------------------------------------------------ record walk
    def _records(self, anchor: int) -> Iterator[tuple[int, int]]:
        """Yield (packet_id, payload_offset) walking the tagged body stream.

        The body opens with one-time metadata packets (variable length); on any
        packet whose size is unknown we resync to the next plausible `anchor`
        record. The resync always searches STRICTLY beyond the current tag, so
        the walk is guaranteed to advance and can never loop.
        """
        buf = self._buf
        n = len(buf)
        pos = self.data_offset
        while pos < n:
            pid = buf[pos] >> 4
            sch = self.schemas.get(pid)
            if pid == 0 or sch is None or sch.size is None:
                nxt = self._find_anchor(anchor, pos + 2)   # payload start > pos+1
                if nxt is None:
                    return
                pos = nxt - 1
                continue
            yield pid, pos + 1
            pos += 1 + sch.size

    def _find_anchor(self, pid: int, start: int) -> int | None:
        """Locate the first plausible payload start for `pid` at/after `start`:
        the tag byte before it must carry `pid`, and the payload's date/time
        fields must be sane."""
        buf = self._buf
        n = len(buf)
        start = max(start, self.data_offset + 1)
        if pid == PKT9:
            for p in range(start, n - PKT9_SIZE):
                if buf[p - 1] >> 4 != PKT9:
                    continue
                yr = struct.unpack_from("<H", buf, p + 4)[0]
                if (2000 <= yr <= 2100 and 1 <= buf[p + 6] <= 12 and 1 <= buf[p + 7] <= 31
                        and buf[p + 8] <= 23 and buf[p + 9] <= 59 and buf[p + 10] <= 61):
                    return p
        elif pid == PKT4:
            for p in range(start, n - PKT4_SIZE):
                if buf[p - 1] >> 4 != PKT4:
                    continue
                ms = struct.unpack_from("<H", buf, p + 7)[0]
                if (buf[p] <= 5 and 15 <= buf[p + 1] <= 99 and 1 <= buf[p + 2] <= 12
                        and 1 <= buf[p + 3] <= 31 and buf[p + 4] <= 23 and buf[p + 5] <= 59
                        and buf[p + 6] <= 61 and ms < 1000):
                    return p
        return None

    # ------------------------------------------------------------------ AdMos
    def raw_packet9(self) -> Iterator[tuple]:
        """Yield each pkt9 record as the raw 32-tuple (matches asiDecoder.exe CSV)."""
        sch = self.schemas[PKT9]
        if sch.fmt is None or sch.size != PKT9_SIZE:
            raise ValueError("unexpected packet-9 schema in this file")
        buf = self._buf
        unpack = struct.Struct(sch.fmt).unpack_from
        for pid, payload_off in self._records(PKT9):
            if pid == PKT9:
                yield unpack(buf, payload_off)

    def gps_track(self) -> Iterator[dict]:
        """Yield decoded AdMos GPS samples with physical units applied."""
        for r in self.raw_packet9():
            d = dict(zip(PKT9_FIELDS, r))
            try:
                ts = datetime(d["year"], d["month"], d["day"], d["hour"],
                              d["minute"], d["second"], tzinfo=timezone.utc)
                utc = ts.isoformat()
            except ValueError:
                utc = None
            yield {
                "utc": utc,
                "iTOW_ms": d["iTOW"],
                "lat_deg": d["lat"] * 1e-7,
                "lon_deg": d["lon"] * 1e-7,
                "height_m": d["height"] * 1e-3,
                "hMSL_m": d["hMSL"] * 1e-3,
                "gSpeed_mps": d["gSpeed"] * 1e-3,
                "headMot_deg": d["headMot"] * 1e-5,
                "numSV": d["numSV"],
                "fixType": d["fixType"],
            }

    # ---------------------------------------------------------------- Protern
    def raw_protern(self) -> Iterator[tuple[int, tuple]]:
        """Yield (packet_id, raw tuple) for every packet-4 and packet-15 record,
        in stream order (matches asiDecoder.exe packet_04 / packet_15 CSVs).

        Known difference from the .exe: it silently drops the rare packet-15
        record whose imu3 field is exactly -32768 (INT16_MIN, ~1 in 50k). Those
        are genuine 0.1 s samples — their deltas/speed are consistent with their
        neighbours and keeping them makes the sample count between keyframes
        equal 10*dt exactly — so this decoder keeps them."""
        s4, s15 = self.schemas.get(PKT4), self.schemas.get(PKT15)
        if s4 is None or s4.fmt is None or s4.size != PKT4_SIZE:
            raise ValueError("unexpected packet-4 schema in this file")
        if s15 is None or s15.fmt is None or s15.size != PKT15_SIZE:
            raise ValueError("unexpected packet-15 schema in this file")
        buf = self._buf
        u4 = struct.Struct(s4.fmt).unpack_from
        u15 = struct.Struct(s15.fmt).unpack_from
        for pid, off in self._records(PKT4):
            if pid == PKT15:
                yield PKT15, u15(buf, off)
            elif pid == PKT4:
                yield PKT4, u4(buf, off)

    def raw_packet4(self) -> Iterator[tuple]:
        return (r for pid, r in self.raw_protern() if pid == PKT4)

    def raw_packet15(self) -> Iterator[tuple]:
        return (r for pid, r in self.raw_protern() if pid == PKT15)

    def protern_track(self) -> dict:
        """Reconstruct the Protern 10 Hz absolute track from keyframes + deltas.

        Packet 4 gives an absolute fix at irregular keyframes; packet 15 gives a
        record every 0.1 s whose marker is -1 on the record coinciding with the
        k-th keyframe (the counts match one-to-one). Each keyframe record takes
        the keyframe's absolute position; every following record adds its
        North/East/Down delta (1e-4 m). Integrated deltas reach the next
        keyframe to within ~0.5 m; that closure residual is spread linearly over
        the segment so the track stays continuous (a hard reset at keyframes
        would inject position jumps and hence speed spikes downstream).

        Closure is still applied when a segment is short by at most
        CLOSURE_MAX_MISSING records (a dropped sample or two — validated against
        Protern's own CSV export: 26-29 m -> 5-10 m in such segments). Segments
        missing more than that (logging paused) get no closure and are timed
        forward from their keyframe (the pause sits at the END of the segment —
        confirmed against the CSV timestamps); records before the first keyframe
        are dropped (no absolute reference).

        Returns numpy arrays: t (datetime64[ns] UTC), lat_deg, lon_deg, alt_m,
        gspeed_mps, fix_type, timestamp (4 kHz uptime ticks), keyframe (bool).
        """
        import numpy as np

        keys, rows = [], []
        for pid, r in self.raw_protern():
            (keys if pid == PKT4 else rows).append(r)
        empty = {k: np.zeros(0) for k in ("lat_deg", "lon_deg", "alt_m", "gspeed_mps",
                                          "fix_type", "timestamp")}
        empty["t"] = np.zeros(0, dtype="datetime64[ns]")
        empty["keyframe"] = np.zeros(0, dtype=bool)
        if not keys or not rows:
            return empty
        K = np.array(keys, dtype=float)          # (nk, 13)
        S = np.array(rows, dtype=float)          # (ns, 9)
        kidx = np.where(S[:, 0] == -1)[0]        # stream rows that are keyframes
        nk = min(len(kidx), len(K))
        if nk == 0:
            return empty
        kidx, K = kidx[:nk], K[:nk]

        # keyframe absolute times (UTC) as ns since epoch
        kt = np.empty(nk, dtype="datetime64[ns]")
        for i, k in enumerate(K):
            try:
                kt[i] = np.datetime64(datetime(2000 + int(k[1]), int(k[2]), int(k[3]),
                                               int(k[4]), int(k[5]), int(k[6])), "ns") \
                    + np.timedelta64(int(k[7]) * 1_000_000, "ns")
            except ValueError:
                kt[i] = np.datetime64("NaT")
        R = 6378137.0
        deg_per_m = 180.0 / (np.pi * R)

        first, last = kidx[0], len(S)
        N = last - first
        t = np.empty(N, dtype="datetime64[ns]")
        lat = np.empty(N); lon = np.empty(N); alt = np.empty(N)
        fix = np.empty(N); ts = np.empty(N); iskey = np.zeros(N, dtype=bool)
        dN = S[:, 6] * 1e-4; dE = S[:, 7] * 1e-4; dD = S[:, 8] * 1e-4
        for i in range(nk):
            a = kidx[i]
            b = kidx[i + 1] if i + 1 < nk else last     # segment rows [a, b)
            n = b - a
            k = K[i]
            lat0, lon0, alt0 = k[9] * 1e-7, k[10] * 1e-7, k[11] * 1e-3
            coslat = np.cos(np.radians(lat0))
            # cumulative displacement from the keyframe (row a itself = 0)
            cN = np.concatenate([[0.0], np.cumsum(dN[a + 1:b])])
            cE = np.concatenate([[0.0], np.cumsum(dE[a + 1:b])])
            cD = np.concatenate([[0.0], np.cumsum(dD[a + 1:b])])
            # closure: spread the residual to the next keyframe over a segment that
            # is complete or short by at most a few dropped samples
            if i + 1 < nk and not np.isnat(kt[i]) and not np.isnat(kt[i + 1]):
                dt_s = (kt[i + 1] - kt[i]) / np.timedelta64(1, "s")
                missing = int(round(10.0 * dt_s)) - n
                if 0 <= missing <= CLOSURE_MAX_MISSING and n > 1:
                    k2 = K[i + 1]
                    totN = cN[-1] + dN[b]            # displacement through the next keyframe row
                    totE = cE[-1] + dE[b]
                    totD = cD[-1] + dD[b]
                    rN = (k2[9] * 1e-7 - lat0) / deg_per_m - totN
                    rE = (k2[10] * 1e-7 - lon0) / (deg_per_m / coslat) - totE
                    rD = -(k2[11] * 1e-3 - alt0) - totD
                    w = np.arange(n) / float(n)
                    cN = cN + rN * w
                    cE = cE + rE * w
                    cD = cD + rD * w
            lat[a - first:b - first] = lat0 + cN * deg_per_m
            lon[a - first:b - first] = lon0 + cE * deg_per_m / coslat
            alt[a - first:b - first] = alt0 - cD
            fix[a - first:b - first] = k[0]
            ts[a - first:b - first] = k[12] + np.arange(n) * 400.0     # 4 kHz ticks per 0.1 s
            t[a - first:b - first] = kt[i] + (np.arange(n) * 100_000_000).astype("timedelta64[ns]")
            iskey[a - first] = True
        return {
            "t": t, "lat_deg": lat, "lon_deg": lon, "alt_m": alt,
            "gspeed_mps": S[first:last, 5] * 1e-3, "fix_type": fix,
            "timestamp": ts, "keyframe": iskey,
        }


def write_packet9_csv(asi_path: str, csv_path: str) -> int:
    """Write the raw pkt9 records to CSV (same columns as asiDecoder.exe). Returns row count.

    Unlike the legacy asiDecoder.exe (which aborts unless a ``RESULT`` folder
    already exists), this creates the output's parent directory as needed.
    """
    import csv as _csv
    import os as _os
    parent = _os.path.dirname(csv_path)
    if parent:
        _os.makedirs(parent, exist_ok=True)
    asi = AsiFile.open(asi_path)
    n = 0
    with open(csv_path, "w", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(PKT9_FIELDS)
        for row in asi.raw_packet9():
            w.writerow(row)
            n += 1
    return n


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python asi_decoder.py FILE.ASI [out.csv]")
        raise SystemExit(2)
    src = sys.argv[1]
    asi = AsiFile.open(src)
    if asi.is_protern:
        tr = asi.protern_track()
        print(f"Protern file: {len(tr['t'])} samples at 10 Hz "
              f"({tr['t'][0]} .. {tr['t'][-1]})" if len(tr["t"]) else "Protern file: no track")
    else:
        out = sys.argv[2] if len(sys.argv) > 2 else src.rsplit(".", 1)[0] + "_packet9.csv"
        count = write_packet9_csv(src, out)
        print(f"wrote {count} GPS records -> {out}")
