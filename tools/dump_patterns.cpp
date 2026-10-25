#include "rules.h"
#include <cstdio>
#include <cctype>
int main(int, char **argv) {
    RuleSet rs = load_rules(argv[1], 100000);
    printf("patterns: %zu   skipped: %zu\n\n", rs.patterns.size(), rs.skipped);
    for (size_t i=0;i<rs.patterns.size();++i){
        printf("%2zu [%2zu] \"", i, rs.patterns[i].size());
        for(unsigned char c: rs.patterns[i])
            if (isprint(c)) putchar(c); else printf("\\x%02x", c);
        printf("\"\n");
    }
}
