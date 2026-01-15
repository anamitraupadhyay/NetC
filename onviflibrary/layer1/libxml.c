#include <libxml/parser.h>
#include <libxml/tree.h>

xmlInitParser(); 
LIBXML_TEST_VERSION

xmlDoc *doc = xmlParseFile("example.xml");
if (doc == NULL) {
    fprintf(stderr, "Failed to parse document\n");
    return;
}
