# XML Parser Transition: From Simple String Parsing to libxml2

## Overview

This document explains the transition from simple string-based XML parsing to using the libxml2 library for the ONVIF Camera Emulator project. It also includes a comparison with Swift's XMLParser and LLVM-based C-Swift interoperability.

---

## Table of Contents

1. [Why libxml2?](#why-libxml2)
2. [Original Simple Parser Implementation](#original-simple-parser-implementation)
3. [libxml2 Implementation](#libxml2-implementation)
4. [API Reference](#api-reference)
5. [Usage Examples](#usage-examples)
6. [Building with libxml2](#building-with-libxml2)
7. [Swift XMLParser Interop with C](#swift-xmlparser-interop-with-c)
8. [Performance Considerations](#performance-considerations)

---

## Why libxml2?

### Problems with Simple String Parsing

The original implementation used `strstr()` and string manipulation:

```c
// Original simple parser - fragile and error-prone
const char *start = strstr(msg, "<server_port>");
if (start) {
    start += strlen("<server_port>");
    char *end = strstr(start, "</server_port>");
    // ...
}
```

**Issues:**
1. **No XML validation** - Malformed XML silently produces wrong results
2. **Namespace ignorance** - Fails with `<ns:server_port>` or `<a:MessageID>`
3. **Whitespace sensitivity** - Breaks with `<server_port >` or newlines
4. **No entity decoding** - `&amp;` `&lt;` etc. not handled
5. **Buffer overflow risks** - Manual string handling is error-prone
6. **No CDATA support** - `<![CDATA[...]]>` not handled

### Benefits of libxml2

1. **Standards compliant** - Full XML 1.0/1.1 support
2. **Namespace aware** - Proper handling of XML namespaces
3. **XPath support** - Powerful query language for XML
4. **Entity handling** - Automatic decoding of XML entities
5. **Validation** - DTD and Schema validation available
6. **Memory safety** - Well-tested library with proper memory management
7. **Performance** - Highly optimized C implementation

---

## Original Simple Parser Implementation

### Config Parser (config.h)

```c
// BEFORE: Simple string-based parsing
static int read_config_port(void) {
    FILE *fp = fopen("config.xml", "r");
    if (!fp) return DEFAULT_CAMERA_HTTP_PORT;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char *port_start = strstr(line, "<server_port>");
        if (port_start) {
            port_start += strlen("<server_port>");
            char *port_end = strstr(port_start, "</server_port>");
            if (port_end) {
                *port_end = '\0';
                int port = atoi(port_start);
                fclose(fp);
                return port;
            }
        }
    }
    fclose(fp);
    return DEFAULT_CAMERA_HTTP_PORT;
}
```

**Problems:**
- Line-based reading may split elements
- No whitespace handling
- No validation

### MessageID Extractor (discovery_server.h)

```c
// BEFORE: Manual string searching
void getmessageid(const char *msg, char *out, size_t out_size) {
    const char *start = strstr(msg, "<wsa:MessageID");
    if (!start) start = strstr(msg, "<a:MessageID");
    if (!start) start = strstr(msg, "<MessageID");
    if (!start) { out[0] = '\0'; return; }
    
    start = strchr(start, '>');
    if (!start) { out[0] = '\0'; return; }
    start++;
    
    const char *end = strstr(start, "</");
    // ...
}
```

**Problems:**
- Must manually handle each namespace prefix
- Doesn't handle attributes on elements
- No proper closing tag matching

### Username/Password Extractor (auth_server.h)

```c
// BEFORE: Fragile SOAP parsing
void extract_username(const char *msg, char *out, size_t out_size) {
    const char *start = strstr(msg, "Username>");
    if (!start) return;
    start += 9;  // Magic number!
    
    const char *end = strstr(start, "</");
    // ...
}
```

**Problems:**
- Magic numbers (9 = length of "Username>")
- Assumes specific formatting
- No namespace support

---

## libxml2 Implementation

### xml_parser.h - Core Functions

```c
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

// Initialize libxml2 (call once at startup)
static inline void xml_parser_init(void) {
    xmlInitParser();
    LIBXML_TEST_VERSION
}

// Cleanup (call at shutdown)
static inline void xml_parser_cleanup(void) {
    xmlCleanupParser();
}
```

### Element Extraction with Tree Walking

```c
/**
 * Extract text content from any element by name (ignores namespaces)
 */
static int xml_extract_element_text(const char *xml_content, 
                                    const char *element_name,
                                    char *output, 
                                    size_t output_size) {
    xmlDocPtr doc = xmlReadMemory(xml_content, strlen(xml_content), 
                                   "noname.xml", NULL, 
                                   XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!doc) return 0;
    
    xmlNodePtr root = xmlDocGetRootElement(doc);
    
    // BFS traversal to find element
    // ... (see xml_parser.h for full implementation)
    
    xmlFreeDoc(doc);
    return found;
}
```

### XPath-Based Extraction

```c
/**
 * Extract using XPath expression
 * Example: xml_extract_xpath(xml, "//server_port", buf, sizeof(buf))
 */
static int xml_extract_xpath(const char *xml_content,
                             const char *xpath_expr,
                             char *output,
                             size_t output_size) {
    xmlDocPtr doc = xmlReadMemory(xml_content, strlen(xml_content),
                                   "noname.xml", NULL, 0);
    if (!doc) return 0;
    
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    xmlXPathObjectPtr obj = xmlXPathEvalExpression(
        (const xmlChar *)xpath_expr, ctx);
    
    if (obj && obj->nodesetval && obj->nodesetval->nodeNr > 0) {
        xmlChar *content = xmlNodeGetContent(obj->nodesetval->nodeTab[0]);
        // Copy to output...
        xmlFree(content);
    }
    
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctx);
    xmlFreeDoc(doc);
    return found;
}
```

### XPath with Namespace Support

```c
/**
 * Extract using XPath with registered namespaces
 */
static int xml_extract_xpath_ns(const char *xml_content,
                                const char *xpath_expr,
                                const char **namespaces,
                                char *output,
                                size_t output_size) {
    // ... setup doc and context ...
    
    // Register namespaces: {"wsa", "http://...", "wsse", "http://...", NULL}
    for (int i = 0; namespaces[i]; i += 2) {
        xmlXPathRegisterNs(ctx, 
                          (const xmlChar *)namespaces[i],
                          (const xmlChar *)namespaces[i+1]);
    }
    
    // Execute XPath with namespace prefixes
    xmlXPathObjectPtr obj = xmlXPathEvalExpression(
        (const xmlChar *)xpath_expr, ctx);
    // ...
}
```

---

## API Reference

### Initialization

| Function | Description |
|----------|-------------|
| `xml_parser_init()` | Initialize libxml2. Call once at program start. |
| `xml_parser_cleanup()` | Cleanup libxml2. Call at program end. |

### Element Extraction

| Function | Description |
|----------|-------------|
| `xml_extract_element_text(xml, element, out, size)` | Extract element by local name (ignores namespace) |
| `xml_extract_xpath(xml, xpath, out, size)` | Extract using XPath expression |
| `xml_extract_xpath_ns(xml, xpath, ns[], out, size)` | Extract using XPath with namespaces |
| `xml_file_extract_element(file, element, out, size)` | Parse file and extract element |

### ONVIF-Specific Functions

| Function | Description |
|----------|-------------|
| `xml_extract_message_id(soap, out, size)` | Extract MessageID from WS-Discovery |
| `xml_is_probe_message(soap)` | Check if message is a Probe |
| `xml_extract_username(soap, out, size)` | Extract Username from SOAP security header |
| `xml_extract_password(soap, out, size)` | Extract Password from SOAP security header |

---

## Usage Examples

### Reading Config File

```c
// BEFORE (simple parser)
int port = read_config_port();  // Uses strstr()

// AFTER (libxml2)
#include "xml_parser.h"

int main() {
    xml_parser_init();
    
    char port_str[16];
    if (xml_file_extract_element("config.xml", "server_port", 
                                  port_str, sizeof(port_str))) {
        int port = atoi(port_str);
        printf("Port: %d\n", port);
    }
    
    xml_parser_cleanup();
    return 0;
}
```

### Parsing SOAP Message

```c
// BEFORE
void getmessageid(const char *msg, char *out, size_t size) {
    const char *start = strstr(msg, "<wsa:MessageID");
    // ... manual parsing ...
}

// AFTER
void getmessageid(const char *msg, char *out, size_t size) {
    if (!xml_extract_message_id(msg, out, size)) {
        out[0] = '\0';
    }
}
```

### Checking Message Type

```c
// BEFORE
bool isprobe(const char *msg) {
    return strstr(msg, "Probe") && 
           strstr(msg, "http://schemas.xmlsoap.org/ws/2005/04/discovery");
}

// AFTER
bool isprobe(const char *msg) {
    return xml_is_probe_message(msg);
}
```

### Extracting Credentials

```c
// BEFORE
extract_username(buf, user, sizeof(user));
extract_passwd(buf, pass, sizeof(pass));

// AFTER
xml_extract_username(buf, user, sizeof(user));
xml_extract_password(buf, pass, sizeof(pass));
```

---

## Building with libxml2

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install libxml2-dev

# Fedora/RHEL
sudo dnf install libxml2-devel

# macOS
brew install libxml2
```

### Compilation

```bash
# Get compiler flags
pkg-config --cflags --libs libxml-2.0
# Output: -I/usr/include/libxml2 -lxml2

# Compile
gcc -o main main.c $(pkg-config --cflags --libs libxml-2.0) -lpthread

# Or in Makefile
CFLAGS += $(shell pkg-config --cflags libxml-2.0)
LDFLAGS += $(shell pkg-config --libs libxml-2.0)
```

### CMake Integration

```cmake
find_package(LibXml2 REQUIRED)
target_include_directories(fakecamera PRIVATE ${LIBXML2_INCLUDE_DIR})
target_link_libraries(fakecamera ${LIBXML2_LIBRARIES})
```

---

## Swift XMLParser Interop with C

This section demonstrates how to achieve similar XML parsing functionality using Swift's `XMLParser` while maintaining C interoperability through LLVM's native interop mechanisms.

### Why Swift XMLParser?

- **Native Apple platforms support** - Built into Foundation
- **Event-driven parsing** - SAX-style, memory efficient
- **Automatic memory management** - ARC handles cleanup
- **Unicode support** - Full UTF-8/16 handling

### Swift XMLParser Implementation

```swift
// File: XMLParserBridge.swift

import Foundation

/// Delegate for parsing XML and extracting specific elements
class ONVIFXMLParser: NSObject, XMLParserDelegate {
    private var currentElement = ""
    private var foundElement = ""
    private var targetElement: String
    private var result: String?
    
    init(targetElement: String) {
        self.targetElement = targetElement
    }
    
    func parse(xmlString: String) -> String? {
        guard let data = xmlString.data(using: .utf8) else { return nil }
        let parser = XMLParser(data: data)
        parser.delegate = self
        parser.parse()
        return result
    }
    
    // MARK: - XMLParserDelegate
    
    func parser(_ parser: XMLParser, 
                didStartElement elementName: String,
                namespaceURI: String?, 
                qualifiedName qName: String?,
                attributes: [String: String] = [:]) {
        // Handle namespaced elements (e.g., "wsa:MessageID" -> "MessageID")
        let localName = elementName.components(separatedBy: ":").last ?? elementName
        currentElement = localName
    }
    
    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if currentElement == targetElement {
            foundElement += string
        }
    }
    
    func parser(_ parser: XMLParser, 
                didEndElement elementName: String,
                namespaceURI: String?, 
                qualifiedName qName: String?) {
        let localName = elementName.components(separatedBy: ":").last ?? elementName
        if localName == targetElement && !foundElement.isEmpty {
            result = foundElement.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if localName == currentElement {
            foundElement = ""
        }
    }
}

/// Extract element text from XML string
func extractElement(from xml: String, elementName: String) -> String? {
    let parser = ONVIFXMLParser(targetElement: elementName)
    return parser.parse(xmlString: xml)
}
```

### C-Swift Interop Using LLVM

Swift code can be called from C using the `@_cdecl` attribute or by creating a C-compatible bridge. Here's how to expose Swift XML parsing functions to C:

```swift
// File: XMLParserBridge.swift

import Foundation

/// C-compatible function to extract element from XML
/// 
/// @param xmlContent Null-terminated XML string
/// @param elementName Element name to find
/// @param output Output buffer
/// @param outputSize Size of output buffer
/// @return 1 on success, 0 on failure
@_cdecl("swift_xml_extract_element")
public func swift_xml_extract_element(
    _ xmlContent: UnsafePointer<CChar>,
    _ elementName: UnsafePointer<CChar>,
    _ output: UnsafeMutablePointer<CChar>,
    _ outputSize: Int
) -> Int32 {
    let xml = String(cString: xmlContent)
    let element = String(cString: elementName)
    
    guard let result = extractElement(from: xml, elementName: element) else {
        output[0] = 0  // Empty string
        return 0
    }
    
    let bytes = result.utf8CString
    let copyLen = min(bytes.count, outputSize - 1)
    
    bytes.withUnsafeBufferPointer { ptr in
        output.assign(from: ptr.baseAddress!, count: copyLen)
    }
    output[copyLen] = 0  // Null terminate
    
    return 1
}

/// C-compatible function to check if message is a Probe
@_cdecl("swift_xml_is_probe")
public func swift_xml_is_probe(_ xmlContent: UnsafePointer<CChar>) -> Int32 {
    let xml = String(cString: xmlContent)
    
    // Check for Probe element
    if let _ = extractElement(from: xml, elementName: "Probe") {
        return 1
    }
    
    // Check Action contains discovery/Probe
    if let action = extractElement(from: xml, elementName: "Action") {
        if action.contains("discovery") && action.contains("Probe") {
            return 1
        }
    }
    
    return 0
}

/// C-compatible function to extract MessageID
@_cdecl("swift_xml_extract_message_id")
public func swift_xml_extract_message_id(
    _ xmlContent: UnsafePointer<CChar>,
    _ output: UnsafeMutablePointer<CChar>,
    _ outputSize: Int
) -> Int32 {
    return swift_xml_extract_element(xmlContent, "MessageID", output, outputSize)
}
```

### C Header for Swift Functions

```c
// File: swift_xml_parser.h

#ifndef SWIFT_XML_PARSER_H
#define SWIFT_XML_PARSER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Extract element text from XML using Swift XMLParser
 * 
 * @param xml_content Null-terminated XML string
 * @param element_name Element name to find
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @return 1 on success, 0 on failure
 */
int32_t swift_xml_extract_element(
    const char *xml_content,
    const char *element_name,
    char *output,
    int output_size
);

/**
 * Check if SOAP message is a WS-Discovery Probe
 */
int32_t swift_xml_is_probe(const char *xml_content);

/**
 * Extract MessageID from WS-Discovery message
 */
int32_t swift_xml_extract_message_id(
    const char *xml_content,
    char *output,
    int output_size
);

#ifdef __cplusplus
}
#endif

#endif // SWIFT_XML_PARSER_H
```

### Using Swift Functions from C

```c
// File: main.c

#include <stdio.h>
#include "swift_xml_parser.h"

int main() {
    const char *soap_xml = 
        "<?xml version=\"1.0\"?>"
        "<Envelope>"
        "<Header>"
        "<MessageID>urn:uuid:12345</MessageID>"
        "</Header>"
        "<Body><Probe/></Body>"
        "</Envelope>";
    
    char message_id[256];
    
    if (swift_xml_extract_message_id(soap_xml, message_id, sizeof(message_id))) {
        printf("MessageID: %s\n", message_id);
    }
    
    if (swift_xml_is_probe(soap_xml)) {
        printf("This is a Probe message\n");
    }
    
    return 0;
}
```

### Building with Swift and C

```bash
# Compile Swift to object file
swiftc -emit-object -o XMLParserBridge.o XMLParserBridge.swift

# Compile C code
clang -c -o main.o main.c

# Link together
clang -o main main.o XMLParserBridge.o \
    -L$(xcode-select -p)/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx \
    -lswiftCore -lswiftFoundation
```

### CMake for Mixed Swift/C Project

```cmake
cmake_minimum_required(VERSION 3.16)
project(ONVIFEmulator LANGUAGES C Swift)

# Swift library
add_library(XMLParserBridge STATIC XMLParserBridge.swift)
target_compile_options(XMLParserBridge PRIVATE -enable-library-evolution)

# C executable
add_executable(fakecamera main.c)
target_link_libraries(fakecamera XMLParserBridge)
```

---

## Performance Considerations

### libxml2 vs Simple String Parser

| Operation | Simple Parser | libxml2 |
|-----------|--------------|---------|
| Parse small XML (<1KB) | ~1μs | ~10μs |
| Parse medium XML (~10KB) | ~5μs | ~50μs |
| Memory allocation | Minimal | More allocations |
| Correctness | Error-prone | Guaranteed |
| Namespace handling | Manual | Automatic |

**Recommendation:** For ONVIF applications where correctness is critical and messages are typically <10KB, the overhead of libxml2 is negligible compared to network latency.

### libxml2 vs Swift XMLParser

| Aspect | libxml2 | Swift XMLParser |
|--------|---------|-----------------|
| Platform | Cross-platform | Apple platforms (Linux limited) |
| Memory | Manual management | ARC |
| Speed | Faster | Slightly slower |
| Ease of use | Moderate | Easy |
| C integration | Native | Requires bridging |

**Recommendation:** Use libxml2 for cross-platform C/Linux applications. Use Swift XMLParser for Apple-platform apps or when Swift is already in use.

---

## Migration Checklist

- [ ] Install libxml2 development package
- [ ] Include `xml_parser.h` in source files
- [ ] Call `xml_parser_init()` at program start
- [ ] Replace string-based parsing with `xml_extract_*` functions
- [ ] Update Makefile/CMakeLists.txt with libxml2 flags
- [ ] Call `xml_parser_cleanup()` at program end
- [ ] Test with malformed XML to verify error handling
- [ ] Update documentation

---

## Conclusion

Transitioning from simple string-based XML parsing to libxml2 provides:

1. **Reliability** - Standards-compliant parsing
2. **Security** - Proper bounds checking and validation
3. **Maintainability** - Clear API instead of string manipulation
4. **Flexibility** - XPath queries and namespace support

For ONVIF applications, this transition ensures proper handling of SOAP messages from various clients that may format their XML differently while remaining semantically valid.

The Swift XMLParser alternative demonstrates how to achieve similar functionality in Swift while maintaining C interoperability, useful for mixed-language projects or Apple platform development.
