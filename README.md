# XMLStream.py ⚙️📡

**Stream massive XML (e.g., Nmap) into JSONL / SQLite / MySQL-dump / Mongo-ready JSONL — safely, fast, and with tiny memory.**

---

## Overview 🚀

`xmlstream.py` converts huge XML files into useful, importable formats **without loading the whole tree into RAM**. It uses `lxml.etree.iterparse` with aggressive element clearing to keep memory flat even on multi‑gigabyte inputs.

* **Generic mode** for any XML
* **Nmap-aware mode** for clean, per‑host JSON objects (ports, services, scripts, OS guesses)
* **Outputs:** JSONL (default), SQLite DB, MySQL `.sql` dump, or Mongo‑ready JSONL
* **Graceful** on Ctrl‑C (finishes current record, closes files/DB)

> With no arguments and no piped input, it prints **help** instead of waiting on stdin.

---

## Quick Start ⚡

```bash
# Convert Nmap XML -> JSONL (one host per line)
python3 xmlstream.py --mode nmap --record-tag host -i scan.xml -o hosts.jsonl

# Convert generic XML on stdin -> JSONL
cat big.xml | python3 xmlstream.py -o out.jsonl

# Nmap XML -> SQLite
python3 xmlstream.py --mode nmap --record-tag host --format sqlite --sqlite-db scan.db -i scan.xml

# Nmap XML -> MySQL dump (import with: mysql mydb < out.sql)
python3 xmlstream.py --mode nmap --record-tag host --format mysql-sql -i scan.xml -o out.sql

# Nmap XML -> MongoDB (jsonl is mongoimport-friendly)
mongoimport --db mydb --collection nmap_hosts --type json --file hosts.jsonl
```

---

## Installation 🛠️

Requirements:

* Python **3.8+**
* `lxml` (C‑accelerated) — install with:

```bash
python3 -m pip install lxml
```

SQLite support uses Python’s stdlib `sqlite3` (no extra install). MySQL dump output is just a text file; no connector needed.

---

## Command Line 🧾

```text
Stream massive XML into JSONL / SQLite / MySQL-dump / Mongo JSONL

Options:
  -i, --input FILE         Input XML file (default: - for stdin)
  -o, --output FILE        Output file (jsonl/mysql-sql) or '-' for stdout
      --format {jsonl,sqlite,mysql-sql,mongo-jsonl}
                           Output format (default: jsonl)
      --mode {generic,nmap}
                           Parsing mode (default: generic). 'nmap' expects <host>.
      --record-tag TAG     Treat TAG elements as records (e.g., 'host' for Nmap)
      --pretty             Pretty-print JSON (slower, larger)
      --sqlite-db PATH     SQLite DB path (required if --format=sqlite)
      --sqlite-table NAME  SQLite table name (default: records)
      --batch N            SQLite batch insert size (default: 500)

Behavior niceties:
- If run with no args **and** no piped input, prints help + usage tips.
- Ctrl‑C requests a soft stop: finishes current record and exits cleanly.
```

---

## Modes 🔀

### Generic Mode 🧩

* Every element matching `--record-tag` becomes a JSON object.
* Attributes are emitted as keys prefixed with `@`.
* Text content appears under `#text` (when attributes/children exist) or as the value when the element is “leafy”.
* A `_tag` field is added for convenience.

**Example**

```xml
<items>
  <item id="1">Alpha</item>
  <item id="2"><name>Beta</name><note>Hi</note></item>
</items>
```

Outputs (JSONL):

```json
{"_tag":"item","@id":"1","#text":"Alpha"}
{"_tag":"item","@id":"2","name":"Beta","note":"Hi"}
```

### Nmap Mode 🧭

* Use `--mode nmap --record-tag host`.
* Produces compact per‑host JSON objects including addresses, hostnames, ports (state/service/CPE/scripts), host scripts, OS matches, uptime when present.

**Sample host (truncated):**

```json
{
  "_tag": "host",
  "starttime": "1724201000",
  "status": "up",
  "addresses": [{"addr": "192.168.1.10", "addrtype": "ipv4"}],
  "hostnames": [{"name": "web01.local", "type": "user"}],
  "ports": [
    {
      "protocol": "tcp",
      "portid": 80,
      "state": "open",
      "service": {"name": "http", "product": "nginx", "version": "1.24"},
      "scripts": [{"id": "http-title", "output": "Welcome"}]
    }
  ]
}
```

---

## Output Formats 📤

### JSONL (default) 🧱

* One JSON object per line (easy to stream/process/`jq`/`mongoimport`).
* Use `--pretty` sparingly for debugging (it’s bigger & slower).

### SQLite (`--format sqlite`) 🗃️

* Creates a DB with a single table (default `records`):

```sql
CREATE TABLE IF NOT EXISTS records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag TEXT,
  json TEXT NOT NULL,
  added_at TEXT DEFAULT (datetime('now'))
);
```

* JSON is stored as TEXT; use JSON1 functions for queries.

**Examples:**

```bash
sqlite3 scan.db "SELECT COUNT(*) FROM records;"

# All open ports from nmap mode
sqlite3 scan.db '
SELECT json_extract(p.value, "$.portid") AS port,
       json_extract(p.value, "$.service.name") AS svc
FROM records, json_each(records.json, "$.ports") AS p
WHERE json_extract(p.value, "$.state") = "open";
'
```

### MySQL Dump (`--format mysql-sql`) 🐬

* Writes a `.sql` file with `CREATE TABLE` + `INSERT` statements using a `JSON` column (MySQL 5.7+):

```sql
CREATE TABLE IF NOT EXISTS `records` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `tag` VARCHAR(128) NULL,
  `json` JSON NOT NULL,
  `added_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**Import:**

```bash
mysql -u user -p mydb < out.sql
```

### Mongo-ready JSONL (`--format mongo-jsonl`) 🍃

* Same as JSONL; named for clarity with `mongoimport`.

---

## Performance Tips ⚡

* **Always set `--record-tag`** for large XML to avoid serializing unrelated branches.
* Avoid `--pretty` for bulk conversions.
* Pipe directly to downstream tools to skip intermediate files when possible.

---

## Error Handling & Signals 🚨

* **XML errors:** prints a descriptive message and returns exit code **2**.
* **Ctrl‑C / SIGINT:** triggers a soft stop — finishes the current record, flushes, closes resources.
* **Missing arguments:** help text is printed when appropriate (no args and no stdin).

---

## Exit Codes 🧾

* `0` — Success (including graceful interruption)
* `2` — XML syntax error
* `>0` — Other failures surfaced by Python/runtime

---

## Troubleshooting 🩹

* **It “just sits there.”** You probably ran it with no args and no pipe in an older version. In the current version, it prints help. Otherwise, provide `-i file.xml` or pipe input.
* **Memory climbs on huge files.** Ensure you set `--record-tag` and you’re using the shipped streaming build (not a modified DOM parse).
* **SQLite import seems slow.** Increase `--batch` (e.g., 2000) and run on SSD. Consider disabling `--pretty`.

---

## Programmatic Notes (Advanced) 🧑‍💻

While `xmlstream.py` is designed as a CLI, the internals are reusable:

* `stream_xml(source, record_tag, mode)` yields one Python dict per record.
* Writers: `write_jsonl`, `write_sqlite`, `write_mysql_sql` can be called from other scripts.

---

## Roadmap 🗺️

* Nessus‑aware and OpenVAS‑aware modes
* Optional direct connectors (MySQL/Mongo) with retry/backoff
* Pluggable normalizers for other security scanners

---

## C++ Companion: `xml2stream` ⚙️

A native, streaming converter written in C++ for high‑throughput scenarios and minimal runtime deps.

**Key features**

* Streaming parser via **libxml2 `xmlTextReader`** (pull‑based; tiny memory footprint)
* Modes: `generic` (any XML) and `nmap` (normalized `<host>` objects)
* Formats: `jsonl`, `mysql-sql`, and **`sqlite`** (when compiled with `-DWITH_SQLITE`)
* Prints **help** when run with no args and no piped input
* **Graceful SIGINT**: finishes the current record, flushes, exits cleanly
* Safe defaults (uses `XML_PARSE_NONET` when available to block external entity/network fetches)

### Dependencies 📦

* Build tools: `g++` (C++17)
* Libraries: `libxml2-dev`, `nlohmann-json3-dev`
* Optional (for `--format sqlite`): `libsqlite3-dev`

**Install on Debian/Ubuntu** 🧰

```bash
sudo apt-get update
sudo apt-get install -y build-essential libxml2-dev nlohmann-json3-dev
# optional for SQLite output
sudo apt-get install -y libsqlite3-dev
```

### Build 🏗️

```bash
# Base build (JSONL + MySQL dump)
g++ -O2 -std=c++17 xmlstream.cpp -o xml2stream $(pkg-config --cflags --libs libxml-2.0)

# With SQLite output enabled
g++ -O2 -std=c++17 xmlstream.cpp -o xml2stream \
  $(pkg-config --cflags --libs libxml-2.0) -DWITH_SQLITE -lsqlite3
```

### Usage ▶️

```bash
# Nmap XML -> JSONL (one host per line)
./xml2stream --mode nmap --record-tag host -i scan.xml -o out.jsonl

# Generic XML on stdin -> JSONL (record per <item>)
cat big.xml | ./xml2stream --mode generic --record-tag item -o -

# Nmap XML -> MySQL dump (.sql import file)
./xml2stream --mode nmap --record-tag host --format mysql-sql -i scan.xml -o scan.sql
mysql -u user -p mydb < scan.sql

# Nmap XML -> SQLite (requires -DWITH_SQLITE at build)
./xml2stream --mode nmap --record-tag host --format sqlite --sqlite-db scan.db -i scan.xml
```

> 💡 **Note:** `--record-tag` is required to define what counts as a “row”. For Nmap, use `host`. For other XML, set it to the repeating element you want.

### Smoke test 🧪

```bash
printf '<root><item id="1">A</item><item id="2">B</item></root>' \
 | ./xml2stream --mode generic --record-tag item -o -
```

Expected output (JSONL):

```json
{"_tag":"item","@id":"1","#text":"A"}
{"_tag":"item","@id":"2","#text":"B"}
```

### Performance & notes 📈

* Prefer `jsonl` for streaming and tooling compatibility (e.g., `jq`, `mongoimport`).
* `mysql-sql` writes a ready‑to‑import dump with a `JSON` column (MySQL 5.7+).
* SQLite writes to a single `records(tag TEXT, json TEXT, added_at TEXT)` table; tune `--batch` for throughput.
* Use `--pretty` only for debugging; it reduces throughput and increases file size.

### Troubleshooting

* **It prints help and exits:** you ran it without args and no piped input; pass `-i` or pipe XML.
* **Compiler errors about help text:** ensure you’re using this version (fixed string assembly; no broken `<<` chains across `#ifdef`).
* **`xmlReaderForFd` arg mismatch:** this build uses the correct signature `(fd, URL, encoding, options)`.

## License 📄

TBD — fill in your project’s license here (e.g., MIT).

---

\$1- **cpp v1.0** — Initial C++ companion (`xml2stream`) with jsonl/mysql-sql outputs and optional SQLite; help‑on‑no‑args; SIGINT soft‑stop.

* **v1.1** — Help on no-args/no-stdin, improved Nmap normalization, MySQL dump.
* **v1.0** — Initial streaming converter with JSONL & SQLite.
