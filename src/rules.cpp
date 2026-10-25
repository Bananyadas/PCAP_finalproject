// rules.cpp — pull content patterns out of Snort/Suricata rules.
//
// A rule looks like:
//   alert tcp any any -> any 80 (msg:"EVIL"; content:"/admin.php?cmd=";
//       content:"|90 90 90|"; nocase; sid:2001234;)
//
// We take every content:"..." string. Each becomes one pattern with its own
// sig_id. Rules with several contents therefore yield several patterns; the
// host side can group them back by sid later if we ever implement full rule
// semantics (we do not — see the Scope section of the report).
//
// Supported escapes inside a content string:
//   |41 42 43|   hex bytes
//   \"  \\  \;   literal quote, backslash, semicolon
//
// Deliberately NOT supported (skipped, with a count reported):
//   pcre:, byte_test:, distance/within offsets, negated content (!"...")
// Those need full rule evaluation, which is outside this project's scope.

#include "rules.h"
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace {

// Convert one content:"..." body into raw bytes. Returns false if the body
// contains something we cannot represent.
bool decode_content(const std::string &in, std::string &out) {
    out.clear();
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];

        if (c == '|') {                       // hex run: |90 90 90|
            size_t end = in.find('|', i + 1);
            if (end == std::string::npos) return false;
            std::istringstream hex(in.substr(i + 1, end - i - 1));
            std::string tok;
            while (hex >> tok) {
                if (tok.size() != 2 || !isxdigit((unsigned char)tok[0])
                                    || !isxdigit((unsigned char)tok[1]))
                    return false;
                out.push_back((char)strtol(tok.c_str(), nullptr, 16));
            }
            i = end;
            continue;
        }

        if (c == '\\' && i + 1 < in.size()) {  // escaped char
            char n = in[++i];
            if (n == '"' || n == '\\' || n == ';') { out.push_back(n); continue; }
            return false;                      // unknown escape, skip the rule
        }

        out.push_back(c);
    }
    return !out.empty();
}

// Find the body of the next content:"..." starting at or after `from`.
// Returns the body, or empty string when there are no more.
std::string next_content(const std::string &line, size_t &from) {
    const std::string key = "content:";
    while (true) {
        size_t k = line.find(key, from);
        if (k == std::string::npos) { from = line.size(); return ""; }

        size_t q = line.find('"', k + key.size());
        if (q == std::string::npos) { from = line.size(); return ""; }

        // negated content (!"...") — not supported, skip this one
        bool negated = false;
        for (size_t j = k + key.size(); j < q; ++j)
            if (line[j] == '!') negated = true;

        // find the closing quote, honouring backslash escapes
        size_t e = q + 1;
        while (e < line.size()) {
            if (line[e] == '\\') { e += 2; continue; }
            if (line[e] == '"') break;
            ++e;
        }
        if (e >= line.size()) { from = line.size(); return ""; }

        std::string body = line.substr(q + 1, e - q - 1);
        from = e + 1;
        if (!negated && !body.empty()) return body;
        // negated or empty: keep looking on the same line
    }
}

} // namespace

RuleSet load_rules(const std::string &path, size_t max_patterns) {
    RuleSet rs;
    std::ifstream f(path);
    if (!f) {
        fprintf(stderr, "rules: cannot open %s\n", path.c_str());
        return rs;
    }

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;

        size_t cursor = 0;
        while (rs.patterns.size() < max_patterns) {
            std::string body = next_content(line, cursor);
            if (body.empty()) break;

            std::string bytes;
            if (!decode_content(body, bytes)) { ++rs.skipped; continue; }
            if (bytes.size() > 255) { ++rs.skipped; continue; }  // absurdly long

            rs.patterns.push_back(bytes);
        }
        if (rs.patterns.size() >= max_patterns) break;
    }
    return rs;
}
