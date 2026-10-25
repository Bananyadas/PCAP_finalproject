#ifndef IDS_RULES_H
#define IDS_RULES_H

#include <string>
#include <vector>

// One pattern per entry; its index is its sig_id.
struct RuleSet {
    std::vector<std::string> patterns;
    size_t skipped = 0;   // content strings we could not represent
};

// Read a Snort/Suricata .rules file and extract content patterns.
// max_patterns caps the set (2000 is plenty for our experiments).
RuleSet load_rules(const std::string &path, size_t max_patterns = 2000);

#endif
