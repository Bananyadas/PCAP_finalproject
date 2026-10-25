// test_cpu.cpp — build the automaton, plant known signatures in a synthetic
// payload, and check the matcher finds exactly those and nothing else.
//
// Runs anywhere, no GPU needed. This is the gate: if these fail, do not
// bother running the CUDA version.

#include "cpu_match.h"
#include "pfac.h"
#include "rules.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int failures = 0;

static void check(bool ok, const char *what) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

// Build a one-segment batch over `text` and return the matches found.
static std::vector<Match> scan(const PfacTable &t, const std::string &text,
                               uint32_t carry = 0) {
    Segment seg;
    seg.flow_id = 0;
    seg.offset  = 0;
    seg.len     = (uint32_t)text.size();
    seg.carry   = carry;

    std::vector<Match> out;
    uint64_t steps = 0;
    cpu_match_segment(t, (const uint8_t *)text.data(), seg, 0, out, &steps);
    sort_matches(out);
    return out;
}

int main() {
    // -----------------------------------------------------------------
    printf("1. Rule parsing\n");
    // -----------------------------------------------------------------
    RuleSet rs = load_rules("rules/sample.rules", 2000);
    printf("     %zu patterns, %zu content strings skipped\n",
           rs.patterns.size(), rs.skipped);
    check(rs.patterns.size() >= 5, "extracted patterns from sample rules");

    bool found_hex = false;
    for (const auto &p : rs.patterns)
        if (p.size() == 3 && (unsigned char)p[0] == 0x90
                          && (unsigned char)p[1] == 0x90
                          && (unsigned char)p[2] == 0x90) found_hex = true;
    check(found_hex, "decoded |90 90 90| into three raw bytes");

    // -----------------------------------------------------------------
    printf("2. Automaton build\n");
    // -----------------------------------------------------------------
    std::vector<std::string> pats = {
        "/admin.php?cmd=",   // 0
        "/admin",            // 1  shares a prefix with 0
        "SELECT * FROM",     // 2
        "\x90\x90\x90",      // 3  binary
        "evilbot"            // 4
    };
    PfacTable t = pfac_build(pats);
    printf("     %u states, %u patterns, L_max = %u, table = %.1f KB\n",
           t.num_states, t.num_patterns, t.max_pat_len,
           pfac_table_bytes(t) / 1024.0);
    check(t.num_patterns == 5, "pattern count");
    check(t.max_pat_len == 15, "L_max is the longest pattern (/admin.php?cmd=)");

    // -----------------------------------------------------------------
    printf("3. Matching\n");
    // -----------------------------------------------------------------
    {
        std::string text = "GET /admin.php?cmd=ls HTTP/1.1";
        auto m = scan(t, text);
        // "/admin" and "/admin.php?cmd=" both start at offset 4
        check(m.size() == 2, "nested patterns both reported");
        bool both = m.size() == 2 && m[0].pos == 4 && m[1].pos == 4
                 && ((m[0].sig_id == 0 && m[1].sig_id == 1)
                  || (m[0].sig_id == 1 && m[1].sig_id == 0));
        check(both, "shorter pattern does not hide the longer one");
    }
    {
        std::string text = "nothing to see here";
        check(scan(t, text).empty(), "clean traffic produces no alerts");
    }
    {
        std::string text = "aa\x90\x90\x90zz";
        auto m = scan(t, text);
        check(m.size() == 1 && m[0].sig_id == 3 && m[0].pos == 2,
              "binary pattern found at the right offset");
    }
    {
        // same pattern twice in one payload
        std::string text = "evilbot and evilbot";
        auto m = scan(t, text);
        check(m.size() == 2 && m[0].pos == 0 && m[1].pos == 12,
              "repeated pattern reported once per occurrence");
    }

    // -----------------------------------------------------------------
    printf("4. Carry de-duplication\n");
    // -----------------------------------------------------------------
    // Ananya Das cuts a flow between batches and copies L_max-1 bytes across.
    // Segment B below starts with 12 carried bytes: "GET /admin.p".
    //   "/admin"          at pos 4, ends at 10 <= 12 -> wholly inside the
    //                      carry, so segment A already reported it -> drop
    //   "/admin.php?cmd=" at pos 4, ends at 19 >  12 -> crosses the cut,
    //                      invisible to A            -> keep
    {
        std::string segB = "GET /admin.php?cmd=id";
        auto m = scan(t, segB, /*carry=*/12);
        bool has_long = false, has_short = false;
        for (auto &x : m) {
            if (x.sig_id == 0) has_long  = true;
            if (x.sig_id == 1) has_short = true;
        }
        check(has_long,  "boundary-spanning signature is still detected");
        check(!has_short, "signature already seen in the previous segment is dropped");
    }
    {
        // the rule itself, in isolation
        check( carry_keeps_match(10, 4, 8), "match after the carry region kept");
        check(!carry_keeps_match(2,  4, 8), "match inside the carry region dropped");
        check( carry_keeps_match(6,  4, 8), "match straddling the boundary kept");
    }

    // -----------------------------------------------------------------
    printf("5. Cost measurement\n");
    // -----------------------------------------------------------------
    {
        std::string cheap(2000, 'Z');            // nothing matches anything
        std::string pricey;
        for (int i = 0; i < 100; ++i) pricey += "/admin.php?cmd=x";

        Segment s1 = {0, 0, (uint32_t)cheap.size(),  0};
        Segment s2 = {0, 0, (uint32_t)pricey.size(), 0};
        std::vector<Match> m1, m2;
        uint64_t c1 = 0, c2 = 0;
        cpu_match_segment(t, (const uint8_t *)cheap.data(),  s1, 0, m1, &c1);
        cpu_match_segment(t, (const uint8_t *)pricey.data(), s2, 0, m2, &c2);

        printf("     %zu bytes of filler  -> %llu steps (%.2f per byte)\n",
               cheap.size(),  (unsigned long long)c1, (double)c1 / cheap.size());
        printf("     %zu bytes of attacks -> %llu steps (%.2f per byte)\n",
               pricey.size(), (unsigned long long)c2, (double)c2 / pricey.size());
        double ratio = ((double)c2 / pricey.size()) / ((double)c1 / cheap.size());
        printf("     cost ratio %.2fx per byte\n", ratio);
        check(ratio > 1.5, "signature-rich payload costs more per byte than filler");
        printf("     ^ this is the per-byte skew Ananya Das's composer exploits.\n"
               "       It is modest here because the sample patterns are short;\n"
               "       with the full ET ruleset the spread is much wider.\n");
    }

    pfac_free(&t);
    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
