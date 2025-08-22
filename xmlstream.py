#!/usr/bin/env python3
"""
xmlstream.py — Stream-convert massive XML to JSONL / SQLite / MySQL-dump / Mongo JSONL.

Features:
- Streaming with lxml.etree.iterparse (no full DOM in memory)
- Generic mode (any XML) OR --mode nmap for smarter Nmap host extraction
- Outputs:
  - jsonl (default): one JSON object per line
  - sqlite: writes a SQLite DB with a records(tag, json) table (JSON stored as TEXT)
  - mysql-sql: emits a .sql file with CREATE TABLE + INSERT statements (JSON column if MySQL 5.7+)
  - mongo-jsonl: alias of jsonl for easy `mongoimport`
- Ctrl-C safe: stops gracefully, flushes, closes DB/files
- Examples at bottom of --help
"""
import sys
import os
import json
import argparse
import signal
import sqlite3
from collections import defaultdict
from datetime import datetime
from typing import Optional, Iterable

from lxml import etree

STOP_REQUESTED = False

def handle_sigint(signum, frame):
    # Soft stop, finish current record and exit cleanly
    global STOP_REQUESTED
    STOP_REQUESTED = True

signal.signal(signal.SIGINT, handle_sigint)

def etree_to_dict(elem):
    """Generic XML element -> dict (attributes as '@', text as '#text', children merged)."""
    d = {elem.tag: {} if elem.attrib else None}
    children = list(elem)
    if children:
        dd = defaultdict(list)
        for child in children:
            for k, v in etree_to_dict(child).items():
                dd[k].append(v)
        d = {elem.tag: {k: v[0] if len(v) == 1 else v for k, v in dd.items()}}
    if elem.attrib:
        d[elem.tag].update(('@' + k, v) for k, v in elem.attrib.items())
    text = (elem.text or '').strip()
    if text:
        if children or elem.attrib:
            d[elem.tag]['#text'] = text
        else:
            d[elem.tag] = text
    return d

# ---------------------- Nmap-specific extraction (per <host>) ----------------------

def nmap_host_to_obj(host_elem: etree._Element) -> dict:
    """Parse an <host> subtree from Nmap XML into a compact JSON object."""
    obj = {}
    # host times & status
    obj['starttime'] = host_elem.get('starttime')
    status = host_elem.find('status')
    if status is not None:
        obj['status'] = status.get('state')

    # addresses
    addrs = []
    for a in host_elem.findall('address'):
        addrs.append({
            'addr': a.get('addr'),
            'addrtype': a.get('addrtype'),
            'vendor': a.get('vendor')
        })
    if addrs: obj['addresses'] = addrs

    # hostnames
    hn = host_elem.find('hostnames')
    if hn is not None:
        names = [{'name': h.get('name'), 'type': h.get('type')} for h in hn.findall('hostname')]
        if names: obj['hostnames'] = names

    # OS guesses (optional)
    os_elem = host_elem.find('os')
    if os_elem is not None:
        matches = []
        for m in os_elem.findall('osmatch'):
            item = {'name': m.get('name'), 'accuracy': m.get('accuracy')}
            classes = []
            for oc in m.findall('osclass'):
                classes.append({
                    'type': oc.get('type'),
                    'vendor': oc.get('vendor'),
                    'osfamily': oc.get('osfamily'),
                    'osgen': oc.get('osgen'),
                    'accuracy': oc.get('accuracy')
                })
            if classes: item['osclass'] = classes
            matches.append(item)
        if matches:
            obj['osmatch'] = matches

    # Ports
    ports_list = []
    ports = host_elem.find('ports')
    if ports is not None:
        for p in ports.findall('port'):
            port_obj = {
                'protocol': p.get('protocol'),
                'portid': safe_int(p.get('portid')),
            }
            state = p.find('state')
            if state is not None:
                port_obj['state'] = state.get('state')
                port_obj['reason'] = state.get('reason')
            service = p.find('service')
            if service is not None:
                svc = {k: service.get(k) for k in (
                    'name','product','version','extrainfo','tunnel','method','conf'
                ) if service.get(k) is not None}
                # gather <cpe> children
                cpes = [c.text for c in service.findall('cpe') if c.text]
                if cpes: svc['cpe'] = cpes
                if svc: port_obj['service'] = svc
            scripts = []
            for s in p.findall('script'):
                scripts.append({'id': s.get('id'), 'output': s.get('output')})
            if scripts: port_obj['scripts'] = scripts
            ports_list.append(port_obj)
    if ports_list: obj['ports'] = ports_list

    # host-level scripts
    hs = []
    for s in host_elem.findall('hostscript/script'):
        hs.append({'id': s.get('id'), 'output': s.get('output')})
    if hs: obj['hostscripts'] = hs

    # uptime (optional)
    up = host_elem.find('uptime')
    if up is not None:
        obj['uptime'] = {'seconds': safe_int(up.get('seconds')), 'lastboot': up.get('lastboot')}

    return obj

def safe_int(v: Optional[str]) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None

# ---------------------- Streaming conversion core ----------------------

def stream_xml(
    source, record_tag: Optional[str], mode: str, huge: bool = True
) -> Iterable[dict]:
    """
    Yield one JSON-able Python object per 'record'.
    - generic: emit each matched element as element->dict
    - nmap: emit per <host> using nmap_host_to_obj
    """
    recover = True
    parser = etree.iterparse(
        source, events=('end',), tag=(record_tag or '*'),
        huge_tree=huge, recover=recover
    )
    root = None
    for _, elem in parser:
        if root is None:
            root = elem.getroottree()
        if STOP_REQUESTED:
            break

        if mode == 'nmap' and elem.tag == 'host':
            record = nmap_host_to_obj(elem)
            record['_tag'] = 'host'
            yield record
        elif mode == 'generic':
            record = etree_to_dict(elem)
            # For top-level convenience, bubble out the sole key
            ((tag, payload),) = record.items()
            yield {'_tag': tag, **({'_text': payload} if not isinstance(payload, dict) else payload)}
        # memory release pattern
        elem.clear()
        while elem.getprevious() is not None:
            del elem.getparent()[0]
        # Note: no need to clear root; let GC reclaim after loop.

def write_jsonl(records: Iterable[dict], out, pretty: bool):
    for rec in records:
        if STOP_REQUESTED:
            break
        if pretty:
            out.write(json.dumps(rec, ensure_ascii=False, indent=2))
        else:
            out.write(json.dumps(rec, ensure_ascii=False, separators=(',', ':')))
        out.write('\n')
        out.flush()

def write_sqlite(records: Iterable[dict], db_path: str, table: str, batch: int = 500):
    os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT,
                json TEXT NOT NULL,
                added_at TEXT DEFAULT (datetime('now'))
            )
        """)
        buf = []
        for rec in records:
            if STOP_REQUESTED:
                break
            tag = rec.get('_tag')
            js = json.dumps(rec, ensure_ascii=False, separators=(',', ':'))
            buf.append((tag, js))
            if len(buf) >= batch:
                cur.executemany(f"INSERT INTO {table}(tag, json) VALUES(?,?)", buf)
                conn.commit()
                buf.clear()
        if buf:
            cur.executemany(f"INSERT INTO {table}(tag, json) VALUES(?,?)", buf)
            conn.commit()
    finally:
        conn.close()

def write_mysql_sql(records: Iterable[dict], out, table: str):
    # Emits a MySQL-compatible SQL dump that creates a table with a JSON column and inserts rows.
    out.write("-- MySQL dump generated by xmlstream.py\n")
    out.write("SET NAMES utf8mb4; SET FOREIGN_KEY_CHECKS=0;\n")
    out.write(f"""CREATE TABLE IF NOT EXISTS `{table}` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `tag` VARCHAR(128) NULL,
  `json` JSON NOT NULL,
  `added_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n""")
    for rec in records:
        if STOP_REQUESTED:
            break
        tag = rec.get('_tag')
        js = json.dumps(rec, ensure_ascii=False)
        # Escape single quotes for SQL
        js_sql = js.replace("\\", "\\\\").replace("'", "\\'")
        tag_sql = (tag or '').replace("\\", "\\\\").replace("'", "\\'")
        out.write(f"INSERT INTO `{table}`(`tag`,`json`) VALUES('{tag_sql}', CAST('{js_sql}' AS JSON));\n")
        out.flush()
    out.write("SET FOREIGN_KEY_CHECKS=1;\n")

def main():
    p = argparse.ArgumentParser(
        description="Stream massive XML into JSONL / SQLite / MySQL-dump / Mongo JSONL",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:

  # 1) Nmap -> JSONL (one host per line)
  nmap -oX scan.xml 192.168.1.0/24
  python3 xmlstream.py --mode nmap --record-tag host -i scan.xml -o out.jsonl

  # 2) Generic XML -> JSONL from stdin
  cat big.xml | python3 xmlstream.py -o out.jsonl

  # 3) Nmap -> SQLite DB (records table)
  python3 xmlstream.py --mode nmap --record-tag host -i scan.xml --format sqlite --sqlite-db scan.db

  # 4) Nmap -> MySQL dump (import with mysql < out.sql)
  python3 xmlstream.py --mode nmap --record-tag host -i scan.xml --format mysql-sql -o out.sql

  # 5) Mongo import (jsonl works directly)
  mongoimport --db mydb --collection nmap_hosts --type json --file out.jsonl
"""
    )
    p.add_argument('-i', '--input', default='-', help="Input XML file (default: - for stdin)")
    p.add_argument('-o', '--output', default='-', help="Output file (jsonl/mysql-sql) or '-' for stdout")
    p.add_argument('--format', choices=['jsonl', 'sqlite', 'mysql-sql', 'mongo-jsonl'], default='jsonl',
                   help="Output format (default: jsonl)")
    p.add_argument('--mode', choices=['generic', 'nmap'], default='generic',
                   help="Parsing mode (default: generic). 'nmap' expects <host> records.")
    p.add_argument('--record-tag', default=None,
                   help="Element tag to treat as a record (e.g., 'host' for Nmap). Recommended for huge files.")
    p.add_argument('--pretty', action='store_true', help="Pretty-print JSON (slower, bigger).")
    p.add_argument('--sqlite-db', default=None, help="SQLite DB path (required if --format=sqlite)")
    p.add_argument('--sqlite-table', default='records', help="SQLite table name (default: records)")
    p.add_argument('--batch', type=int, default=500, help="SQLite batch insert size (default: 500)")

    # --- INSERT #1: before parse_args() ---
    import sys
    if len(sys.argv) == 1 and sys.stdin.isatty():
        p.print_help()
        print("\nTip: pipe XML in or use -i/--input. Examples:\n"
              "  cat scan.xml | python3 xmlstream.py -o out.jsonl\n"
              "  python3 xmlstream.py -i scan.xml -o out.jsonl")
        return 0

    args = p.parse_args()

    # --- INSERT #2: after parse_args() ---
    if args.input == '-' and sys.stdin.isatty():
        p.print_help()
        print("\nTip: no input detected on stdin. Pipe XML or specify -i/--input.\n"
              "Examples:\n"
              "  cat scan.xml | python3 xmlstream.py -o out.jsonl\n"
              "  python3 xmlstream.py -i scan.xml -o out.jsonl")
        return 0

    # Sensible defaults for nmap mode
    if args.mode == 'nmap' and not args.record_tag:
        args.record_tag = 'host'

    # Open input
    if args.input == '-':
        source = sys.stdin.buffer
    else:
        source = open(args.input, 'rb')

    try:
        records = stream_xml(source, args.record_tag, args.mode)

        if args.format in ('jsonl', 'mongo-jsonl'):
            out = sys.stdout if args.output == '-' else open(args.output, 'w', encoding='utf-8')
            try:
                write_jsonl(records, out, args.pretty)
            finally:
                if out is not sys.stdout:
                    out.close()

        elif args.format == 'sqlite':
            if not args.sqlite_db:
                p.error("--sqlite-db is required when --format=sqlite")
            write_sqlite(records, args.sqlite_db, args.sqlite_table, args.batch)

        elif args.format == 'mysql-sql':
            out = sys.stdout if args.output == '-' else open(args.output, 'w', encoding='utf-8')
            try:
                write_mysql_sql(records, out, table='records')
            finally:
                if out is not sys.stdout:
                    out.close()
        else:
            p.error("Unsupported format.")  # Shouldn't happen

    except etree.XMLSyntaxError as e:
        print(f"[!] XML syntax error: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting cleanly.", file=sys.stderr)
    finally:
        if args.input != '-':
            source.close()

if __name__ == '__main__':
    main()
