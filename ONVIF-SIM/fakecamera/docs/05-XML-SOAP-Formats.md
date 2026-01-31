# XML and SOAP Formats for ONVIF

> Understanding SOAP messages, XML namespaces, and ONVIF-specific message structures

## Table of Contents

1. [SOAP Fundamentals](#soap-fundamentals)
2. [XML Namespaces in ONVIF](#xml-namespaces-in-onvif)
3. [SOAP Envelope Structure](#soap-envelope-structure)
4. [Request Messages](#request-messages)
5. [Response Messages](#response-messages)
6. [WS-Addressing](#ws-addressing)
7. [WS-Security Header](#ws-security-header)
8. [Common ONVIF Message Templates](#common-onvif-message-templates)
9. [Parsing XML in C](#parsing-xml-in-c)

---

## SOAP Fundamentals

### What is SOAP?

SOAP (Simple Object Access Protocol) is a messaging protocol for exchanging structured information. ONVIF uses SOAP 1.2 over HTTP for all service communications.

### SOAP Message Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                        SOAP Envelope                            │
│  xmlns:s="http://www.w3.org/2003/05/soap-envelope"             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                      SOAP Header                          │  │
│  │  (Optional: WS-Security, WS-Addressing, etc.)             │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │ wsse:Security    (Authentication)                   │  │  │
│  │  │ wsa:Action       (Operation being called)           │  │  │
│  │  │ wsa:MessageID    (Unique message identifier)        │  │  │
│  │  │ wsa:RelatesTo    (Response correlation)             │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                       SOAP Body                           │  │
│  │  (The actual request/response data)                       │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │ tds:GetDeviceInformation                            │  │  │
│  │  │ tds:GetSystemDateAndTime                            │  │  │
│  │  │ etc.                                                │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### SOAP 1.2 vs SOAP 1.1

| Feature | SOAP 1.1 | SOAP 1.2 (ONVIF) |
|---------|----------|------------------|
| Namespace | `http://schemas.xmlsoap.org/soap/envelope/` | `http://www.w3.org/2003/05/soap-envelope` |
| Content-Type | `text/xml` | `application/soap+xml` |
| Fault Codes | String | URI |

---

## XML Namespaces in ONVIF

### Common Namespace Prefixes

| Prefix | Namespace URI | Purpose |
|--------|---------------|---------|
| `s` or `soap` | `http://www.w3.org/2003/05/soap-envelope` | SOAP 1.2 envelope |
| `wsa` or `a` | `http://schemas.xmlsoap.org/ws/2004/08/addressing` | WS-Addressing |
| `wsse` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd` | WS-Security |
| `wsu` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd` | WS-Security Utility |
| `tds` | `http://www.onvif.org/ver10/device/wsdl` | Device Service |
| `tt` | `http://www.onvif.org/ver10/schema` | ONVIF types |
| `d` | `http://schemas.xmlsoap.org/ws/2005/04/discovery` | WS-Discovery |
| `dn` | `http://www.onvif.org/ver10/network/wsdl` | Network/Discovery |

### Namespace Declaration

```xml
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
    xmlns:tt="http://www.onvif.org/ver10/schema">
```

---

## SOAP Envelope Structure

### Minimal SOAP Message

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Body>
        <!-- Content here -->
    </s:Body>
</s:Envelope>
```

### Complete SOAP Message with Header

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
    
    <s:Header>
        <wsa:MessageID>urn:uuid:12345678-1234-1234-1234-123456789abc</wsa:MessageID>
        <wsa:Action>http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation</wsa:Action>
        <wsa:To>http://192.168.1.100/onvif/device_service</wsa:To>
    </s:Header>
    
    <s:Body>
        <!-- Request/Response content -->
    </s:Body>
</s:Envelope>
```

---

## Request Messages

### GetSystemDateAndTime (No Authentication)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <s:Body>
        <tds:GetSystemDateAndTime/>
    </s:Body>
</s:Envelope>
```

### GetDeviceInformation (With WS-Security)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
    
    <s:Header>
        <wsse:Security s:mustUnderstand="1">
            <wsse:UsernameToken>
                <wsse:Username>admin</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">
                    qN3x8T5gK2mF1pL7vW4zR9yJ6nM=
                </wsse:Password>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
                    YWJjZGVmZ2hpamtsbW5vcA==
                </wsse:Nonce>
                <wsu:Created>2024-01-15T10:30:45Z</wsu:Created>
            </wsse:UsernameToken>
        </wsse:Security>
        
        <wsa:MessageID>urn:uuid:98765432-1234-1234-1234-123456789abc</wsa:MessageID>
        <wsa:Action>http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation</wsa:Action>
    </s:Header>
    
    <s:Body>
        <tds:GetDeviceInformation/>
    </s:Body>
</s:Envelope>
```

### WS-Discovery Probe

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
    xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
    
    <s:Header>
        <a:Action s:mustUnderstand="1">
            http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe
        </a:Action>
        <a:MessageID>urn:uuid:12345678-1234-1234-1234-123456789abc</a:MessageID>
        <a:To s:mustUnderstand="1">
            urn:schemas-xmlsoap-org:ws:2005:04:discovery
        </a:To>
    </s:Header>
    
    <s:Body>
        <d:Probe>
            <d:Types>dn:NetworkVideoTransmitter</d:Types>
        </d:Probe>
    </s:Body>
</s:Envelope>
```

---

## Response Messages

### GetSystemDateAndTimeResponse

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl" 
    xmlns:tt="http://www.onvif.org/ver10/schema">
    
    <s:Header>
        <a:Action xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse
        </a:Action>
        <a:RelatesTo xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            urn:uuid:request-message-id-here
        </a:RelatesTo>
    </s:Header>
    
    <s:Body>
        <tds:GetSystemDateAndTimeResponse>
            <tds:SystemDateAndTime>
                <tt:DateTimeType>Manual</tt:DateTimeType>
                <tt:DaylightSavings>false</tt:DaylightSavings>
                <tt:TimeZone>
                    <tt:TZ>GMT+05:30</tt:TZ>
                </tt:TimeZone>
                <tt:UTCDateTime>
                    <tt:Time>
                        <tt:Hour>14</tt:Hour>
                        <tt:Minute>30</tt:Minute>
                        <tt:Second>45</tt:Second>
                    </tt:Time>
                    <tt:Date>
                        <tt:Year>2024</tt:Year>
                        <tt:Month>1</tt:Month>
                        <tt:Day>15</tt:Day>
                    </tt:Date>
                </tt:UTCDateTime>
            </tds:SystemDateAndTime>
        </tds:GetSystemDateAndTimeResponse>
    </s:Body>
</s:Envelope>
```

### GetDeviceInformationResponse

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    
    <s:Header>
        <a:Action>
            http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse
        </a:Action>
        <a:RelatesTo>urn:uuid:request-message-id</a:RelatesTo>
        <a:MessageID>urn:uuid:response-message-id</a:MessageID>
    </s:Header>
    
    <s:Body>
        <tds:GetDeviceInformationResponse>
            <tds:Manufacturer>Videonetics</tds:Manufacturer>
            <tds:Model>Videonetics_Camera_Emulator</tds:Model>
            <tds:FirmwareVersion>10.0</tds:FirmwareVersion>
            <tds:SerialNumber>VN001</tds:SerialNumber>
            <tds:HardwareId>1.0</tds:HardwareId>
        </tds:GetDeviceInformationResponse>
    </s:Body>
</s:Envelope>
```

### ProbeMatch (Discovery Response)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
    xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" 
    xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
    
    <s:Header>
        <a:Action s:mustUnderstand="1">
            http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches
        </a:Action>
        <a:MessageID>urn:uuid:response-uuid-here</a:MessageID>
        <a:RelatesTo>urn:uuid:probe-message-id</a:RelatesTo>
        <a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>
    </s:Header>
    
    <s:Body>
        <d:ProbeMatches>
            <d:ProbeMatch>
                <a:EndpointReference>
                    <a:Address>urn:uuid:device-uuid-from-machine-id</a:Address>
                </a:EndpointReference>
                <d:Types>dn:NetworkVideoTransmitter</d:Types>
                <d:Scopes>
                    onvif://www.onvif.org/name/CameraName 
                    onvif://www.onvif.org/auth/1 
                    onvif://www.onvif.org/manufacturer/Videonetics 
                    onvif://www.onvif.org/hardware/VMS 
                    onvif://www.onvif.org/location/India 
                    onvif://www.onvif.org/profile/streaming 
                    onvif://www.onvif.org/type/video_encoder
                </d:Scopes>
                <d:XAddrs>http://192.168.1.100:7000/onvif/device_service</d:XAddrs>
                <d:MetadataVersion>1</d:MetadataVersion>
            </d:ProbeMatch>
        </d:ProbeMatches>
    </s:Body>
</s:Envelope>
```

---

## WS-Addressing

### Purpose

WS-Addressing provides transport-neutral mechanisms to address web services and messages:

- **MessageID** - Unique identifier for each message
- **RelatesTo** - Links response to request
- **Action** - Identifies the operation
- **To** - Destination endpoint

### MessageID Format

```xml
<wsa:MessageID>urn:uuid:12345678-1234-1234-1234-123456789abc</wsa:MessageID>
```

Format: `urn:uuid:` followed by a valid UUID v4

### RelatesTo (Response Correlation)

```xml
<!-- In Request -->
<wsa:MessageID>urn:uuid:abc123</wsa:MessageID>

<!-- In Response -->
<wsa:RelatesTo>urn:uuid:abc123</wsa:RelatesTo>  <!-- Same as request MessageID -->
<wsa:MessageID>urn:uuid:def456</wsa:MessageID>  <!-- New ID for response -->
```

### Action URIs

| Service | Operation | Action URI |
|---------|-----------|------------|
| Device | GetDeviceInformation | `http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation` |
| Device | GetSystemDateAndTime | `http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime` |
| Device | GetCapabilities | `http://www.onvif.org/ver10/device/wsdl/GetCapabilities` |
| Discovery | Probe | `http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe` |
| Discovery | ProbeMatches | `http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches` |

---

## WS-Security Header

### Complete Security Header Structure

```xml
<wsse:Security 
    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    s:mustUnderstand="1">
    
    <wsse:UsernameToken wsu:Id="UsernameToken-1">
        <wsse:Username>admin</wsse:Username>
        
        <wsse:Password 
            Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">
            Base64(SHA1(nonce + created + password))
        </wsse:Password>
        
        <wsse:Nonce 
            EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
            Base64(random_bytes)
        </wsse:Nonce>
        
        <wsu:Created>2024-01-15T10:30:45Z</wsu:Created>
    </wsse:UsernameToken>
</wsse:Security>
```

### Password Types

| Type URI | Description | Security |
|----------|-------------|----------|
| `...#PasswordDigest` | SHA-1 hash | ✅ Recommended |
| `...#PasswordText` | Plain text | ⚠️ Use only with TLS |

### Timestamp Format

ISO 8601 UTC format: `YYYY-MM-DDTHH:MM:SSZ`

Example: `2024-01-15T10:30:45Z`

---

## Common ONVIF Message Templates

### C Template Strings (from tcp_config.h)

```c
// GetSystemDateAndTime Response Template
const char *GET_DATE_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Header>"
        "<a:Action xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">"
            "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse"
        "</a:Action>"
        "<a:RelatesTo xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">%s</a:RelatesTo>"
    "</s:Header>"
    "<s:Body>"
        "<tds:GetSystemDateAndTimeResponse>"
            "<tds:SystemDateAndTime>"
                "<tt:DateTimeType>Manual</tt:DateTimeType>"
                "<tt:DaylightSavings>false</tt:DaylightSavings>"
                "<tt:TimeZone><tt:TZ>GMT+05:30</tt:TZ></tt:TimeZone>"
                "<tt:UTCDateTime>"
                    "<tt:Time>"
                        "<tt:Hour>%d</tt:Hour>"
                        "<tt:Minute>%d</tt:Minute>"
                        "<tt:Second>%d</tt:Second>"
                    "</tt:Time>"
                    "<tt:Date>"
                        "<tt:Year>%d</tt:Year>"
                        "<tt:Month>%d</tt:Month>"
                        "<tt:Day>%d</tt:Day>"
                    "</tt:Date>"
                "</tt:UTCDateTime>"
            "</tds:SystemDateAndTime>"
        "</tds:GetSystemDateAndTimeResponse>"
    "</s:Body>"
"</s:Envelope>";

// Parameters: RelatesTo, Hour, Minute, Second, Year, Month, Day
```

```c
// GetDeviceInformation Response Template
const char *GET_DEVICE_INFO_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
    "<s:Header>"
        "<a:Action>http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse</a:Action>"
        "<a:RelatesTo>%s</a:RelatesTo>"           // 1. Request MessageID
        "<a:MessageID>urn:uuid:%s</a:MessageID>"  // 2. Response UUID
    "</s:Header>"
    "<s:Body>"
        "<tds:GetDeviceInformationResponse>"
            "<tds:Manufacturer>%s</tds:Manufacturer>"       // 3
            "<tds:Model>%s</tds:Model>"                     // 4
            "<tds:FirmwareVersion>%s</tds:FirmwareVersion>" // 5
            "<tds:SerialNumber>%s</tds:SerialNumber>"       // 6
            "<tds:HardwareId>%s</tds:HardwareId>"           // 7
        "</tds:GetDeviceInformationResponse>"
    "</s:Body>"
"</s:Envelope>";
```

### Using Templates in Code

```c
void send_device_info_response(int socket, const char *request_id) {
    char soap_response[2048];
    
    snprintf(soap_response, sizeof(soap_response),
             GET_DEVICE_INFO_TEMPLATE,
             request_id,           // RelatesTo
             "new-uuid-here",      // Response MessageID
             "Videonetics",        // Manufacturer
             "Camera_Emulator",    // Model
             "10.0",               // Firmware
             "VN001",              // Serial
             "1.0");               // Hardware
    
    char http_response[4096];
    snprintf(http_response, sizeof(http_response),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/soap+xml; charset=utf-8\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n%s",
             strlen(soap_response), soap_response);
    
    send(socket, http_response, strlen(http_response), 0);
}
```

---

## Parsing XML in C

### Simple Tag Extraction (from auth_utils.h)

```c
// Extract value between XML tags
void extract_tag_value(const char *msg, const char *tag, char *out, size_t out_size) {
    out[0] = '\0';
    
    // Find the tag (handles both <tag> and <ns:tag>)
    const char *start = strstr(msg, tag);
    if (!start) return;
    
    // Find closing '>'
    start = strchr(start, '>');
    if (!start) return;
    start++;  // Skip '>'
    
    // Find closing tag '</'
    const char *end = strstr(start, "</");
    if (!end) return;
    
    // Copy value
    size_t len = end - start;
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    
    // Trim whitespace
    trim_whitespace(out);
}
```

### Generic Tag Parser (from simpleparser.h)

```c
// Parse specific tag from line
static inline uint8_t get_the_tag(
    const char *line,      // Buffer to read from
    const char *tag,       // Tag name (without <>)
    char *out,             // Output buffer
    size_t out_size        // Output buffer size
) {
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    
    const char *start = strstr(line, open);
    if (!start) return 0;
    
    start += strlen(open);
    
    const char *end = strstr(start, close);
    if (!end) return 0;
    
    size_t len = end - start;
    if (len >= out_size) len = out_size - 1;
    
    memcpy(out, start, len);
    out[len] = '\0';
    
    return 1;
}
```

### Checking for Specific Operations

```c
// Check if message is GetDeviceInformation request
static inline bool is_get_device_information(const char *msg) {
    if (strstr(msg, "GetDeviceInformation") && 
        strstr(msg, "http://www.onvif.org/ver10/device/wsdl")) {
        return true;
    }
    return false;
}

// Check if message is WS-Discovery Probe
bool isprobe(const char *msg) {
    if (strstr(msg, "Probe") && 
        strstr(msg, "http://schemas.xmlsoap.org/ws/2005/04/discovery")) {
        return true;
    }
    return false;
}
```

### MessageID Extraction

```c
void getmessageid(const char *msg, char *out, size_t out_size) {
    // Try different namespace prefixes
    const char *start = strstr(msg, "<wsa:MessageID");
    if (!start) start = strstr(msg, "<a:MessageID");
    if (!start) start = strstr(msg, "<MessageID");
    
    if (!start) {
        out[0] = '\0';
        return;
    }
    
    // Find '>'
    start = strchr(start, '>');
    if (!start) {
        out[0] = '\0';
        return;
    }
    start++;  // Skip '>'
    
    // Find closing tag
    const char *end = strstr(start, "</");
    if (!end) {
        out[0] = '\0';
        return;
    }
    
    size_t len = (size_t)(end - start);
    if (len >= out_size) len = out_size - 1;
    
    memcpy(out, start, len);
    out[len] = '\0';
    
    // Trim whitespace
    while (len > 0 && (out[len-1] == ' ' || out[len-1] == '\n' || out[len-1] == '\r')) {
        out[--len] = '\0';
    }
}
```

---

## Best Practices

### 1. Always Include Namespaces

```xml
<!-- ✅ Good -->
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">

<!-- ❌ Bad -->
<Envelope>
```

### 2. Escape Special Characters

| Character | Escape |
|-----------|--------|
| `<` | `&lt;` |
| `>` | `&gt;` |
| `&` | `&amp;` |
| `"` | `&quot;` |
| `'` | `&apos;` |

### 3. Use Consistent Encoding

```xml
<?xml version="1.0" encoding="UTF-8"?>
```

### 4. Match Content-Type

```http
Content-Type: application/soap+xml; charset=utf-8
```

---

*Continue to [06-HTTP-Protocol-Guide.md](./06-HTTP-Protocol-Guide.md) →*
