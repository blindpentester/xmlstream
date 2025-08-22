// xmlstream.cpp
//
// Stream massive XML into JSONL / MySQL-dump / (optional) SQLite.
// - Modes: generic | nmap
// - Formats: jsonl | mysql-sql | (sqlite with -DWITH_SQLITE)
// - Help shows when no args and no piped stdin.
// - Graceful SIGINT: finishes current record then exits.
//
// Build:
//   deps:
//     sudo apt-get update
//     sudo apt-get install -y build-essential libxml2-dev nlohmann-json3-dev
//   g++ -O2 -std=c++17 xmlstream.cpp -o xml2stream $(pkg-config --cflags --libs libxml-2.0)
//
// With SQLite output:
//   sudo apt-get install -y libsqlite3-dev
//   g++ -O2 -std=c++17 xmlstream.cpp -o xml2stream $(pkg-config --cflags --libs libxml-2.0) -DWITH_SQLITE -lsqlite3
//
// Usage examples:
//   ./xml2stream --mode nmap --record-tag host -i scan.xml -o out.jsonl
//   cat big.xml | ./xml2stream --mode generic --record-tag item -o -
//   ./xml2stream --mode nmap --record-tag host --format mysql-sql -i scan.xml -o scan.sql
//   (sqlite) ./xml2stream --mode nmap --record-tag host --format sqlite --sqlite-db scan.db -i scan.xml

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <algorithm>   // std::max
#include <cstdlib>     // atoi
#include <csignal>
#include <getopt.h>
#include <unistd.h>    // isatty
#include <cstdio>      // fileno

#include <libxml/xmlreader.h>
#include <nlohmann/json.hpp>

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

// ---------- SIGINT handling ----------
static volatile std::sig_atomic_t g_stop_requested = 0;
static void sigint_handler(int) { g_stop_requested = 1; }

// ---------- CLI options ----------
struct Options {
    std::string input = "-";
    std::string output = "-";
    std::string mode = "generic";           // "generic" | "nmap"
    std::string record_tag;                 // e.g., "host" for nmap
    std::string format = "jsonl";           // "jsonl" | "mysql-sql" | "sqlite" (if compiled)
    bool pretty = false;

#ifdef WITH_SQLITE
    bool use_sqlite = false;
    std::string sqlite_db;
    std::string sqlite_table = "records";
    int sqlite_batch = 500;
#endif
};

static void print_help(const char* prog) {
    std::cerr << "Stream massive XML into JSONL / MySQL-dump / (optional) SQLite\n\n";
    std::cerr << "Options:\n";
    std::cerr << "  -i, --input FILE           Input XML file (default: - for stdin)\n";
    std::cerr << "  -o, --output FILE          Output file (default: - for stdout)\n";
    std::cerr << "      --mode MODE            generic | nmap (default: generic)\n";
    std::cerr << "      --record-tag TAG       Treat TAG elements as records (e.g., 'host' for Nmap)\n";
    std::cerr << "      --format FMT           jsonl | mysql-sql";
#ifdef WITH_SQLITE
    std::cerr << " | sqlite";
#endif
    std::cerr << "\n";
    std::cerr << "      --pretty               Pretty-print JSON (slower, larger)\n";
    std::cerr << "  -h, --help                 Show this help\n";
#ifdef WITH_SQLITE
    std::cerr << "\nSQLite options (only when compiled with -DWITH_SQLITE):\n";
    std::cerr << "      --sqlite-db PATH       SQLite DB path (required if --format=sqlite)\n";
    std::cerr << "      --sqlite-table NAME    Table name (default: records)\n";
    std::cerr << "      --batch N              SQLite batch insert size (default: 500)\n";
#endif
    std::cerr << "\nExamples:\n";
    std::cerr << "  # Nmap -> JSONL\n  " << prog << " --mode nmap --record-tag host -i scan.xml -o out.jsonl\n\n";
    std::cerr << "  # Generic XML on stdin -> JSONL\n  cat big.xml | " << prog << " --mode generic --record-tag item -o -\n\n";
    std::cerr << "  # Nmap -> MySQL dump\n  " << prog << " --mode nmap --record-tag host --format mysql-sql -i scan.xml -o scan.sql\n";
}

// ---------- XML -> JSON helpers ----------
static nlohmann::json node_to_json(xmlNodePtr node);

// attributes -> "@key"
static void add_attributes(nlohmann::json& obj, xmlNodePtr node) {
    for (xmlAttr* attr = node->properties; attr; attr = attr->next) {
        xmlChar* value = xmlNodeListGetString(node->doc, attr->children, 1);
        if (value) {
            std::string k = "@" + std::string(reinterpret_cast<const char*>(attr->name));
            obj[k] = std::string(reinterpret_cast<const char*>(value));
            xmlFree(value);
        }
    }
}

// group element children by name; merge text under "#text"
static nlohmann::json children_to_json(xmlNodePtr node) {
    std::map<std::string, std::vector<nlohmann::json>> groups;
    for (xmlNodePtr cur = node->children; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE) {
            nlohmann::json cj = node_to_json(cur);
            groups[std::string(reinterpret_cast<const char*>(cur->name))].push_back(std::move(cj));
        }
    }
    nlohmann::json obj = nlohmann::json::object();
    // merge element children
    for (auto& kv : groups) {
        if (kv.second.size() == 1) {
            const nlohmann::json& single = kv.second.front(); // {"tag": {...}}
            obj[kv.first] = single.at(kv.first);
        } else {
            nlohmann::json arr = nlohmann::json::array();
            for (auto& el : kv.second) arr.push_back(el.at(kv.first));
            obj[kv.first] = std::move(arr);
        }
    }
    // add text content
    xmlChar* content = xmlNodeGetContent(node);
    if (content) {
        std::string txt = std::string(reinterpret_cast<const char*>(content));
        xmlFree(content);
        // trim
        auto start = txt.find_first_not_of(" \t\r\n");
        auto end   = txt.find_last_not_of(" \t\r\n");
        if (start != std::string::npos && end != std::string::npos) {
            std::string trimmed = txt.substr(start, end - start + 1);
            if (!trimmed.empty()) {
                if (!obj.empty()) obj["#text"] = trimmed;
                else obj = trimmed; // leaf
            }
        }
    }
    return obj;
}

static nlohmann::json node_to_json(xmlNodePtr node) {
    std::string name = std::string(reinterpret_cast<const char*>(node->name));
    nlohmann::json inner = nlohmann::json::object();
    add_attributes(inner, node);
    nlohmann::json kids = children_to_json(node);

    if (kids.is_object()) {
        for (auto it = kids.begin(); it != kids.end(); ++it) inner[it.key()] = it.value();
    } else if (!kids.is_null()) {
        if (inner.empty()) inner = kids; else inner["#text"] = kids;
    }
    nlohmann::json out = nlohmann::json::object();
    out[name] = inner.is_null() ? nlohmann::json::object() : inner;
    return out;
}

// ---------- Nmap <host> normalization ----------
static nlohmann::json nmap_host_to_obj(xmlNodePtr host) {
    nlohmann::json out = nlohmann::json::object();

    if (xmlChar* st = xmlGetProp(host, BAD_CAST "starttime")) {
        out["starttime"] = std::string((char*)st); xmlFree(st);
    }

    // status
    for (xmlNodePtr n = host->children; n; n = n->next) {
        if (n->type != XML_ELEMENT_NODE) continue;
        if (std::string((char*)n->name) == "status") {
            if (xmlChar* s = xmlGetProp(n, BAD_CAST "state")) {
                out["status"] = std::string((char*)s); xmlFree(s);
            }
        }
    }

    // addresses
    {
        nlohmann::json arr = nlohmann::json::array();
        for (xmlNodePtr n = host->children; n; n = n->next) {
            if (n->type != XML_ELEMENT_NODE) continue;
            if (std::string((char*)n->name) == "address") {
                nlohmann::json a;
                if (xmlChar* v = xmlGetProp(n, BAD_CAST "addr"))     { a["addr"]     = std::string((char*)v); xmlFree(v); }
                if (xmlChar* v = xmlGetProp(n, BAD_CAST "addrtype")) { a["addrtype"] = std::string((char*)v); xmlFree(v); }
                if (xmlChar* v = xmlGetProp(n, BAD_CAST "vendor"))   { a["vendor"]   = std::string((char*)v); xmlFree(v); }
                arr.push_back(a);
            }
        }
        if (!arr.empty()) out["addresses"] = arr;
    }

    // hostnames
    for (xmlNodePtr n = host->children; n; n = n->next) {
        if (n->type != XML_ELEMENT_NODE) continue;
        if (std::string((char*)n->name) == "hostnames") {
            nlohmann::json names = nlohmann::json::array();
            for (xmlNodePtr h = n->children; h; h = h->next) {
                if (h->type != XML_ELEMENT_NODE) continue;
                if (std::string((char*)h->name) == "hostname") {
                    nlohmann::json hn;
                    if (xmlChar* v = xmlGetProp(h, BAD_CAST "name")) { hn["name"] = std::string((char*)v); xmlFree(v); }
                    if (xmlChar* v = xmlGetProp(h, BAD_CAST "type")) { hn["type"] = std::string((char*)v); xmlFree(v); }
                    names.push_back(hn);
                }
            }
            if (!names.empty()) out["hostnames"] = names;
        }
    }

    // ports
    for (xmlNodePtr n = host->children; n; n = n->next) {
        if (n->type != XML_ELEMENT_NODE) continue;
        if (std::string((char*)n->name) == "ports") {
            nlohmann::json arr = nlohmann::json::array();
            for (xmlNodePtr p = n->children; p; p = p->next) {
                if (p->type != XML_ELEMENT_NODE) continue;
                if (std::string((char*)p->name) == "port") {
                    nlohmann::json pj;
                    if (xmlChar* v = xmlGetProp(p, BAD_CAST "protocol")) pj["protocol"] = std::string((char*)v), xmlFree(v);
                    if (xmlChar* v = xmlGetProp(p, BAD_CAST "portid"))   pj["portid"]   = std::string((char*)v), xmlFree(v);

                    for (xmlNodePtr c = p->children; c; c = c->next) {
                        if (c->type != XML_ELEMENT_NODE) continue;
                        std::string ct((char*)c->name);
                        if (ct == "state") {
                            if (xmlChar* v = xmlGetProp(c, BAD_CAST "state"))  pj["state"]  = std::string((char*)v), xmlFree(v);
                            if (xmlChar* v = xmlGetProp(c, BAD_CAST "reason")) pj["reason"] = std::string((char*)v), xmlFree(v);
                        } else if (ct == "service") {
                            nlohmann::json svc;
                            const char* keys[] = {"name","product","version","extrainfo","tunnel","method","conf"};
                            for (const char* k : keys) {
                                if (xmlChar* v = xmlGetProp(c, BAD_CAST k)) { svc[k] = std::string((char*)v); xmlFree(v); }
                            }
                            nlohmann::json cpes = nlohmann::json::array();
                            for (xmlNodePtr ce = c->children; ce; ce = ce->next) {
                                if (ce->type == XML_ELEMENT_NODE && std::string((char*)ce->name)=="cpe") {
                                    if (xmlChar* t = xmlNodeGetContent(ce)) { cpes.push_back(std::string((char*)t)); xmlFree(t); }
                                }
                            }
                            if (!cpes.empty()) svc["cpe"] = cpes;
                            if (!svc.empty()) pj["service"] = svc;
                        } else if (ct == "script") {
                            if (!pj.contains("scripts")) pj["scripts"] = nlohmann::json::array();
                            nlohmann::json sc;
                            if (xmlChar* v = xmlGetProp(c, BAD_CAST "id"))     sc["id"] = std::string((char*)v), xmlFree(v);
                            if (xmlChar* v = xmlGetProp(c, BAD_CAST "output")) sc["output"] = std::string((char*)v), xmlFree(v);
                            pj["scripts"].push_back(sc);
                        }
                    }
                    arr.push_back(pj);
                }
            }
            if (!arr.empty()) out["ports"] = arr;
        }
    }

    // host-level scripts
    for (xmlNodePtr n = host->children; n; n = n->next) {
        if (n->type != XML_ELEMENT_NODE) continue;
        if (std::string((char*)n->name) == "hostscript") {
            nlohmann::json hs = nlohmann::json::array();
            for (xmlNodePtr s = n->children; s; s = s->next) {
                if (s->type != XML_ELEMENT_NODE || std::string((char*)s->name)!="script") continue;
                nlohmann::json sc;
                if (xmlChar* v = xmlGetProp(s, BAD_CAST "id"))     sc["id"] = std::string((char*)v), xmlFree(v);
                if (xmlChar* v = xmlGetProp(s, BAD_CAST "output")) sc["output"] = std::string((char*)v), xmlFree(v);
                hs.push_back(sc);
            }
            if (!hs.empty()) out["hostscripts"] = hs;
        }
    }

    // uptime
    for (xmlNodePtr n = host->children; n; n = n->next) {
        if (n->type != XML_ELEMENT_NODE) continue;
        if (std::string((char*)n->name) == "uptime") {
            nlohmann::json up;
            if (xmlChar* v = xmlGetProp(n, BAD_CAST "seconds"))  up["seconds"]  = std::string((char*)v), xmlFree(v);
            if (xmlChar* v = xmlGetProp(n, BAD_CAST "lastboot")) up["lastboot"] = std::string((char*)v), xmlFree(v);
            if (!up.empty()) out["uptime"] = up;
        }
    }

    out["_tag"] = "host";
    return out;
}

// ---------- MySQL dump helpers ----------
static std::string sql_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '\'': out += "\\\'"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\0': out += "\\0";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

static void mysql_write_preamble(std::ostream& os, const std::string& table) {
    os << "-- MySQL dump generated by xml2stream\n"
          "SET NAMES utf8mb4; SET FOREIGN_KEY_CHECKS=0;\n"
       << "CREATE TABLE IF NOT EXISTS `" << table << R"(` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `tag` VARCHAR(128) NULL,
  `json` JSON NOT NULL,
  `added_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
)";
}

static void mysql_write_insert(std::ostream& os, const std::string& table,
                               const std::string& tag, const std::string& json_str) {
    os << "INSERT INTO `" << table << "`(`tag`,`json`) VALUES('"
       << sql_escape(tag) << "', CAST('"
       << sql_escape(json_str) << "' AS JSON));\n";
}

static void mysql_write_postamble(std::ostream& os) {
    os << "SET FOREIGN_KEY_CHECKS=1;\n";
}

// ---------- SQLite helpers ----------
#ifdef WITH_SQLITE
static void sqlite_ensure_schema(sqlite3* db, const std::string& table) {
    char* errmsg = nullptr;
    std::string create = "CREATE TABLE IF NOT EXISTS " + table + R"( (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tag TEXT,
        json TEXT NOT NULL,
        added_at TEXT DEFAULT (datetime('now'))
    );)";
    if (sqlite3_exec(db, create.c_str(), nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string e = errmsg ? errmsg : "unknown";
        sqlite3_free(errmsg);
        throw std::runtime_error("SQLite create failed: " + e);
    }
}

static void sqlite_batch_insert(sqlite3* db, const std::string& table,
                                const std::vector<std::pair<std::string,std::string>>& rows) {
    sqlite3_exec(db, "BEGIN;", nullptr, nullptr, nullptr);
    std::string sql = "INSERT INTO " + table + "(tag,json) VALUES(?,?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("SQLite prepare failed");
    }
    for (auto& r : rows) {
        sqlite3_bind_text(stmt, 1, r.first.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, r.second.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            throw std::runtime_error("SQLite step failed");
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }
    sqlite3_finalize(stmt);
    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
}
#endif

// ---------- Main ----------
int main(int argc, char** argv) {
    std::signal(SIGINT, sigint_handler);

    // Help if no args and stdin is a TTY (no pipe)
    if (argc == 1 && isatty(STDIN_FILENO)) {
        print_help(argv[0]);
        std::cerr << "\nTip: pipe XML in or use -i/--input.\n";
        return 0;
    }

    Options opt;

    static option longopts[] = {
        {"input",       required_argument, nullptr, 'i'},
        {"output",      required_argument, nullptr, 'o'},
        {"mode",        required_argument, nullptr,  1 },
        {"record-tag",  required_argument, nullptr,  2 },
        {"format",      required_argument, nullptr,  3 },
        {"pretty",      no_argument,       nullptr,  4 },
#ifdef WITH_SQLITE
        {"sqlite-db",   required_argument, nullptr,  5 },
        {"sqlite-table",required_argument, nullptr,  6 },
        {"batch",       required_argument, nullptr,  7 },
#endif
        {"help",        no_argument,       nullptr, 'h'},
        {0,0,0,0}
    };

    while (true) {
        int idx = 0;
        int c = getopt_long(argc, argv, "i:o:h", longopts, &idx);
        if (c == -1) break;
        switch (c) {
            case 'i': opt.input = optarg; break;
            case 'o': opt.output = optarg; break;
            case 'h': print_help(argv[0]); return 0;
            case 1:   opt.mode = optarg; break;
            case 2:   opt.record_tag = optarg; break;
            case 3:   opt.format = optarg; break;
            case 4:   opt.pretty = true; break;
#ifdef WITH_SQLITE
            case 5:   opt.use_sqlite = true; opt.sqlite_db = optarg; break;
            case 6:   opt.sqlite_table = optarg; break;
            case 7:   opt.sqlite_batch = std::max(1, atoi(optarg)); break;
#endif
            default:  print_help(argv[0]); return 1;
        }
    }

    // Extra guard: input is stdin but no pipe
    if (opt.input == "-" && isatty(STDIN_FILENO)) {
        print_help(argv[0]);
        std::cerr << "\nTip: no input on stdin. Pipe XML or use -i/--input.\n";
        return 0;
    }

    if (opt.mode != "generic" && opt.mode != "nmap") {
        std::cerr << "[!] Invalid --mode\n";
        return 2;
    }
    if (opt.mode == "nmap" && opt.record_tag.empty()) {
        opt.record_tag = "host";
    }
#ifndef WITH_SQLITE
    if (opt.format == "sqlite") {
        std::cerr << "[!] Rebuild with -DWITH_SQLITE to enable --format sqlite\n";
        return 3;
    }
#endif

    // Input reader
    xmlTextReaderPtr reader = nullptr;
    if (opt.input == "-") {
        // xmlReaderForFd(fd, URL, encoding, options)
        reader = xmlReaderForFd(
            fileno(stdin),
            nullptr,
            nullptr,
            XML_PARSE_RECOVER | XML_PARSE_NOBLANKS | XML_PARSE_NOENT
#ifdef XML_PARSE_NONET
            | XML_PARSE_NONET
#endif
        );
    } else {
        reader = xmlReaderForFile(
            opt.input.c_str(),
            nullptr,
            XML_PARSE_RECOVER | XML_PARSE_NOBLANKS | XML_PARSE_NOENT
#ifdef XML_PARSE_NONET
            | XML_PARSE_NONET
#endif
        );
    }
    if (!reader) {
        std::cerr << "[!] Failed to open input\n";
        return 4;
    }

    // Output targets
    std::ostream* pout = &std::cout;
    std::ofstream fout;
#ifdef WITH_SQLITE
    sqlite3* sdb = nullptr;
    std::vector<std::pair<std::string,std::string>> sqlite_buf;
#endif
    bool to_jsonl    = (opt.format == "jsonl");
    bool to_mysql    = (opt.format == "mysql-sql");
#ifdef WITH_SQLITE
    bool to_sqlite   = (opt.format == "sqlite");
#endif

    if (to_jsonl || to_mysql) {
        if (opt.output != "-") {
            fout.open(opt.output, std::ios::out | std::ios::trunc);
            if (!fout) { std::cerr << "[!] Failed to open output\n"; xmlFreeTextReader(reader); return 5; }
            pout = &fout;
        }
    }
#ifdef WITH_SQLITE
    if (to_sqlite) {
        if (opt.sqlite_db.empty()) { std::cerr << "[!] --sqlite-db is required for --format sqlite\n"; xmlFreeTextReader(reader); return 6; }
        if (sqlite3_open(opt.sqlite_db.c_str(), &sdb) != SQLITE_OK) { std::cerr << "[!] SQLite open failed\n"; xmlFreeTextReader(reader); return 7; }
        try { sqlite_ensure_schema(sdb, opt.sqlite_table); }
        catch (const std::exception& ex) { std::cerr << "[!] " << ex.what() << "\n"; sqlite3_close(sdb); xmlFreeTextReader(reader); return 8; }
    }
#endif

    if (to_mysql) {
        mysql_write_preamble(*pout, "records");
    }

    if (opt.record_tag.empty()) {
        std::cerr << "[!] --record-tag is required for streaming conversion.\n";
        xmlFreeTextReader(reader);
        xmlCleanupParser();
        return 9;
    }

    // Streaming loop
    int ret = xmlTextReaderRead(reader);
    while (ret == 1 && !g_stop_requested) {
        int type = xmlTextReaderNodeType(reader);
        if (type == XML_READER_TYPE_ELEMENT) {
            const xmlChar* nm = xmlTextReaderConstName(reader);
            std::string tag = nm ? (const char*)nm : "";

            if (tag == opt.record_tag) {
                xmlNodePtr node = xmlTextReaderExpand(reader);
                if (node && node->type == XML_ELEMENT_NODE) {
                    nlohmann::json j;
                    if (opt.mode == "nmap" && tag == "host") {
                        j = nmap_host_to_obj(node);
                    } else {
                        j = node_to_json(node);
                        auto it = j.begin(); // unwrap {"tag": {...}} -> {..., "_tag": "tag"}
                        if (it != j.end()) { nlohmann::json merged = it.value(); merged["_tag"] = it.key(); j = merged; }
                    }
                    const std::string json_str = opt.pretty ? j.dump(2) : j.dump();
                    const std::string tag_val  = j.contains("_tag") ? j["_tag"].get<std::string>() : opt.record_tag;

#ifdef WITH_SQLITE
                    if (to_sqlite) {
                        sqlite_buf.emplace_back(tag_val, json_str);
                        if ((int)sqlite_buf.size() >= opt.sqlite_batch) {
                            try { sqlite_batch_insert(sdb, opt.sqlite_table, sqlite_buf); }
                            catch (const std::exception& ex) { std::cerr << "[!] SQLite: " << ex.what() << "\n"; }
                            sqlite_buf.clear();
                        }
                    } else
#endif
                    if (to_mysql) {
                        mysql_write_insert(*pout, "records", tag_val, json_str);
                    } else if (to_jsonl) {
                        *pout << json_str << "\n";
                    }
                }
                // Skip subtree quickly
                xmlTextReaderNext(reader);
                ret = xmlTextReaderRead(reader);
                continue;
            }
        }
        ret = xmlTextReaderRead(reader);
    }

#ifdef WITH_SQLITE
    if (!g_stop_requested && (opt.format == "sqlite") && !sqlite_buf.empty()) {
        try { sqlite_batch_insert(sdb, opt.sqlite_table, sqlite_buf); }
        catch (const std::exception& ex) { std::cerr << "[!] SQLite: " << ex.what() << "\n"; }
        sqlite_buf.clear();
    }
#endif

    if (to_mysql) {
        mysql_write_postamble(*pout);
    }

#ifdef WITH_SQLITE
    if (sdb) sqlite3_close(sdb);
#endif
    xmlFreeTextReader(reader);
    xmlCleanupParser();

    if (g_stop_requested) std::cerr << "\n[!] Interrupted. Exiting cleanly.\n";
    return 0;
}
