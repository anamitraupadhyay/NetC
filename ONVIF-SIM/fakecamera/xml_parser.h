/**
 * @file xml_parser.h
 * @brief XML parsing utilities using libxml2
 * 
 * This header provides XML parsing functions using libxml2 library,
 * replacing the simple string-based parsers for better reliability
 * and standards compliance.
 * 
 * Compilation requires: pkg-config --cflags --libs libxml-2.0
 * gcc ... $(pkg-config --cflags --libs libxml-2.0)
 */

#ifndef XML_PARSER_H
#define XML_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

/**
 * @brief Initialize libxml2 parser
 * Call this once at program startup
 */
static inline void xml_parser_init(void) {
    xmlInitParser();
    LIBXML_TEST_VERSION
}

/**
 * @brief Cleanup libxml2 parser
 * Call this at program shutdown
 */
static inline void xml_parser_cleanup(void) {
    xmlCleanupParser();
}

/**
 * @brief Extract text content from a specific XML element
 * 
 * @param xml_content The XML string to parse
 * @param element_name The name of the element to find (without namespace prefix)
 * @param output Buffer to store the extracted text
 * @param output_size Size of the output buffer
 * @return 1 on success, 0 on failure
 */
static int xml_extract_element_text(const char *xml_content, 
                                    const char *element_name,
                                    char *output, 
                                    size_t output_size) {
    if (!xml_content || !element_name || !output || output_size == 0) {
        return 0;
    }
    
    output[0] = '\0';
    
    xmlDocPtr doc = xmlReadMemory(xml_content, (int)strlen(xml_content), 
                                   "noname.xml", NULL, 
                                   XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!doc) {
        return 0;
    }
    
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        xmlFreeDoc(doc);
        return 0;
    }
    
    // Recursive search for the element
    int found = 0;
    xmlNodePtr queue[1024];
    int queue_start = 0, queue_end = 0;
    queue[queue_end++] = root;
    
    while (queue_start < queue_end && !found) {
        xmlNodePtr node = queue[queue_start++];
        
        for (xmlNodePtr cur = node; cur && !found; cur = cur->next) {
            if (cur->type == XML_ELEMENT_NODE) {
                // Check if element name matches (ignoring namespace prefix)
                const char *local_name = (const char *)cur->name;
                if (strcmp(local_name, element_name) == 0) {
                    xmlChar *content = xmlNodeGetContent(cur);
                    if (content) {
                        size_t len = strlen((const char *)content);
                        if (len >= output_size) len = output_size - 1;
                        memcpy(output, content, len);
                        output[len] = '\0';
                        xmlFree(content);
                        found = 1;
                    }
                }
                
                // Add children to queue
                if (cur->children && queue_end < 1024) {
                    queue[queue_end++] = cur->children;
                }
            }
        }
    }
    
    xmlFreeDoc(doc);
    return found;
}

/**
 * @brief Extract text using XPath expression
 * 
 * @param xml_content The XML string to parse
 * @param xpath_expr The XPath expression (e.g., "//server_port")
 * @param output Buffer to store the extracted text
 * @param output_size Size of the output buffer
 * @return 1 on success, 0 on failure
 */
static int xml_extract_xpath(const char *xml_content,
                             const char *xpath_expr,
                             char *output,
                             size_t output_size) {
    if (!xml_content || !xpath_expr || !output || output_size == 0) {
        return 0;
    }
    
    output[0] = '\0';
    
    xmlDocPtr doc = xmlReadMemory(xml_content, (int)strlen(xml_content),
                                   "noname.xml", NULL,
                                   XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!doc) {
        return 0;
    }
    
    xmlXPathContextPtr xpath_ctx = xmlXPathNewContext(doc);
    if (!xpath_ctx) {
        xmlFreeDoc(doc);
        return 0;
    }
    
    xmlXPathObjectPtr xpath_obj = xmlXPathEvalExpression(
        (const xmlChar *)xpath_expr, xpath_ctx);
    
    int found = 0;
    if (xpath_obj && xpath_obj->nodesetval && xpath_obj->nodesetval->nodeNr > 0) {
        xmlNodePtr node = xpath_obj->nodesetval->nodeTab[0];
        xmlChar *content = xmlNodeGetContent(node);
        if (content) {
            size_t len = strlen((const char *)content);
            if (len >= output_size) len = output_size - 1;
            memcpy(output, content, len);
            output[len] = '\0';
            xmlFree(content);
            found = 1;
        }
    }
    
    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
    xmlXPathFreeContext(xpath_ctx);
    xmlFreeDoc(doc);
    
    return found;
}

/**
 * @brief Extract text using XPath with namespace support
 * 
 * @param xml_content The XML string to parse
 * @param xpath_expr The XPath expression with namespace prefixes
 * @param namespaces Array of namespace prefix-URI pairs (e.g., {"a", "http://...", "wsse", "http://...", NULL})
 * @param output Buffer to store the extracted text
 * @param output_size Size of the output buffer
 * @return 1 on success, 0 on failure
 */
static int xml_extract_xpath_ns(const char *xml_content,
                                const char *xpath_expr,
                                const char **namespaces,
                                char *output,
                                size_t output_size) {
    if (!xml_content || !xpath_expr || !output || output_size == 0) {
        return 0;
    }
    
    output[0] = '\0';
    
    xmlDocPtr doc = xmlReadMemory(xml_content, (int)strlen(xml_content),
                                   "noname.xml", NULL,
                                   XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!doc) {
        return 0;
    }
    
    xmlXPathContextPtr xpath_ctx = xmlXPathNewContext(doc);
    if (!xpath_ctx) {
        xmlFreeDoc(doc);
        return 0;
    }
    
    // Register namespaces
    if (namespaces) {
        for (int i = 0; namespaces[i] && namespaces[i+1]; i += 2) {
            xmlXPathRegisterNs(xpath_ctx, 
                              (const xmlChar *)namespaces[i],
                              (const xmlChar *)namespaces[i+1]);
        }
    }
    
    xmlXPathObjectPtr xpath_obj = xmlXPathEvalExpression(
        (const xmlChar *)xpath_expr, xpath_ctx);
    
    int found = 0;
    if (xpath_obj && xpath_obj->nodesetval && xpath_obj->nodesetval->nodeNr > 0) {
        xmlNodePtr node = xpath_obj->nodesetval->nodeTab[0];
        xmlChar *content = xmlNodeGetContent(node);
        if (content) {
            size_t len = strlen((const char *)content);
            if (len >= output_size) len = output_size - 1;
            memcpy(output, content, len);
            output[len] = '\0';
            xmlFree(content);
            found = 1;
        }
    }
    
    if (xpath_obj) xmlXPathFreeObject(xpath_obj);
    xmlXPathFreeContext(xpath_ctx);
    xmlFreeDoc(doc);
    
    return found;
}

/**
 * @brief Check if XML contains a specific element or pattern
 * 
 * @param xml_content The XML string to check
 * @param element_name Element name to search for
 * @return 1 if found, 0 if not found
 */
static int xml_contains_element(const char *xml_content, const char *element_name) {
    char dummy[16];
    return xml_extract_element_text(xml_content, element_name, dummy, sizeof(dummy));
}

/**
 * @brief Read and parse XML file, extract element text
 * 
 * @param filename Path to the XML file
 * @param element_name Element to extract
 * @param output Buffer for output
 * @param output_size Size of output buffer
 * @return 1 on success, 0 on failure
 */
static int xml_file_extract_element(const char *filename,
                                    const char *element_name,
                                    char *output,
                                    size_t output_size) {
    if (!filename || !element_name || !output || output_size == 0) {
        return 0;
    }
    
    output[0] = '\0';
    
    xmlDocPtr doc = xmlReadFile(filename, NULL, 
                                XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!doc) {
        return 0;
    }
    
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        xmlFreeDoc(doc);
        return 0;
    }
    
    // Search for element
    int found = 0;
    for (xmlNodePtr cur = root->children; cur && !found; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE && 
            strcmp((const char *)cur->name, element_name) == 0) {
            xmlChar *content = xmlNodeGetContent(cur);
            if (content) {
                size_t len = strlen((const char *)content);
                if (len >= output_size) len = output_size - 1;
                memcpy(output, content, len);
                output[len] = '\0';
                xmlFree(content);
                found = 1;
            }
        }
    }
    
    xmlFreeDoc(doc);
    return found;
}

// ============================================================================
// ONVIF-Specific Parsing Functions
// ============================================================================

/**
 * @brief Extract MessageID from WS-Discovery message
 * Works with various namespace prefixes (wsa:, a:, or no prefix)
 */
static int xml_extract_message_id(const char *soap_xml, char *output, size_t output_size) {
    // Try different element names that might contain MessageID
    if (xml_extract_element_text(soap_xml, "MessageID", output, output_size)) {
        return 1;
    }
    return 0;
}

/**
 * @brief Check if SOAP message is a WS-Discovery Probe
 */
static int xml_is_probe_message(const char *soap_xml) {
    // Check for Probe element and discovery action
    char action[256] = {0};
    if (xml_extract_element_text(soap_xml, "Action", action, sizeof(action))) {
        if (strstr(action, "discovery") && strstr(action, "Probe")) {
            return 1;
        }
    }
    // Also check for Probe element directly
    if (xml_contains_element(soap_xml, "Probe")) {
        return 1;
    }
    return 0;
}

/**
 * @brief Extract Username from ONVIF SOAP security header
 */
static int xml_extract_username(const char *soap_xml, char *output, size_t output_size) {
    return xml_extract_element_text(soap_xml, "Username", output, output_size);
}

/**
 * @brief Extract Password from ONVIF SOAP security header
 */
static int xml_extract_password(const char *soap_xml, char *output, size_t output_size) {
    return xml_extract_element_text(soap_xml, "Password", output, output_size);
}

#endif // XML_PARSER_H
