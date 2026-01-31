# ONVIF XML & SOAP Messages - Complete Guide

## Table of Contents
1. [Introduction](#introduction)
2. [SOAP Message Structure](#soap-message-structure)
3. [XML Namespaces in ONVIF](#xml-namespaces-in-onvif)
4. [WS-Security Header Structure](#ws-security-header-structure)
5. [ONVIF Service Request/Response Examples](#onvif-service-requestresponse-examples)
6. [XML Parsing Techniques](#xml-parsing-techniques)
7. [SOAP Templates in This Project](#soap-templates-in-this-project)
8. [Constructing ONVIF Messages](#constructing-onvif-messages)
9. [Common Pitfalls and Solutions](#common-pitfalls-and-solutions)
10. [Related Documentation](#related-documentation)

---

## Introduction

**ONVIF** uses SOAP (Simple Object Access Protocol) over HTTP/HTTPS for communication. All ONVIF commands and responses are structured as XML documents following the SOAP 1.2 specification.

### What is SOAP?
- XML-based messaging protocol
- Platform and language-independent
- Consists of: **Envelope**, **Header**, and **Body**
- Uses HTTP POST for transport

### Why XML for ONVIF?
- **Standardized**: Industry-standard format
- **Human-readable**: Easy to debug
- **Extensible**: Support for custom namespaces
- **Interoperable**: Works across all platforms

---

## SOAP Message Structure

### Basic SOAP Envelope Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Header>
        <!-- Authentication, addressing, and metadata -->
    </s:Header>
    <s:Body>
        <!-- Actual ONVIF request or response -->
    </s:Body>
</s:Envelope>
```

### Components Breakdown

| Component | Purpose | Required |
|-----------|---------|----------|
| `<?xml version="1.0"?>` | XML declaration | Yes |
| `<s:Envelope>` | Root element | Yes |
| `<s:Header>` | Metadata, auth, addressing | Optional (but used in ONVIF) |
| `<s:Body>` | Main content | Yes |

### SOAP Envelope Explained

```xml
<s:Envelope 
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
    xmlns:tt="http://www.onvif.org/ver10/schema">
```

- **xmlns:s**: SOAP 1.2 namespace
- **xmlns:tds**: ONVIF Device service namespace
- **xmlns:tt**: ONVIF schema types namespace

---

## XML Namespaces in ONVIF

### Why Namespaces?
Namespaces prevent naming conflicts and organize elements by their specifications.

### Common ONVIF Namespaces

| Prefix | Namespace URI | Purpose |
|--------|---------------|---------|
| `s:` | `http://www.w3.org/2003/05/soap-envelope` | SOAP 1.2 envelope |
| `a:` | `http://schemas.xmlsoap.org/ws/2004/08/addressing` | WS-Addressing |
| `d:` | `http://schemas.xmlsoap.org/ws/2005/04/discovery` | WS-Discovery |
| `tds:` | `http://www.onvif.org/ver10/device/wsdl` | ONVIF Device Management |
| `tt:` | `http://www.onvif.org/ver10/schema` | ONVIF Types/Schema |
| `trt:` | `http://www.onvif.org/ver10/media/wsdl` | ONVIF Media Service |
| `tptz:` | `http://www.onvif.org/ver20/ptz/wsdl` | ONVIF PTZ Service |
| `wsse:` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd` | WS-Security Extension |
| `wsu:` | `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd` | WS-Security Utility |

### Namespace Declaration Examples

```xml
<!-- Declare at envelope level (most common) -->
<s:Envelope xmlns:s="..." xmlns:tds="..." xmlns:tt="...">

<!-- Declare inline (use when needed once) -->
<a:Action xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
    http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime
</a:Action>
```

---

## WS-Security Header Structure

### What is WS-Security?
WS-Security provides message-level authentication for SOAP messages using **UsernameToken** with password digest.

### Full WS-Security Header Example

```xml
<s:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
                   s:mustUnderstand="1">
        <wsse:UsernameToken>
            <wsse:Username>admin</wsse:Username>
            <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">
                fG3zNjQxYzE2ZjA5MzQ3ZTk4ZjEzNzI4ZDM5MTdiY2Q=
            </wsse:Password>
            <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
                MTY1NzU0MzIxMDEyMzQ1Njc4OQ==
            </wsse:Nonce>
            <wsu:Created>2024-01-15T12:30:00Z</wsu:Created>
        </wsse:UsernameToken>
    </wsse:Security>
</s:Header>
```

### WS-Security Components

| Element | Description | Format |
|---------|-------------|--------|
| `<wsse:Username>` | Username | Plain text |
| `<wsse:Password>` | Hashed password | Base64(SHA1(Nonce + Created + Password)) |
| `<wsse:Nonce>` | Random value | Base64 encoded |
| `<wsu:Created>` | Timestamp | ISO 8601 (UTC) |

### Password Digest Algorithm

```
PasswordDigest = Base64( SHA1( Base64Decode(Nonce) + Created + Password ) )
```

Example in C:
```c
// From authhandler/auth_utils.h
unsigned char hash_input[256];
int pos = 0;

// Decode nonce from Base64
unsigned char nonce_raw[64];
int nonce_len = base64_decode(nonce, strlen(nonce), nonce_raw);

// Concatenate: Nonce + Created + Password
memcpy(hash_input + pos, nonce_raw, nonce_len);
pos += nonce_len;
memcpy(hash_input + pos, created, strlen(created));
pos += strlen(created);
memcpy(hash_input + pos, password, strlen(password));
pos += strlen(password);

// SHA1 hash
unsigned char hash[20];
SHA1(hash_input, pos, hash);

// Base64 encode
char digest_b64[64];
base64_encode(hash, 20, digest_b64);
```

---

## ONVIF Service Request/Response Examples

### 1. GetSystemDateAndTime (Unauthenticated)

**Purpose**: Get device time (doesn't require authentication per ONVIF spec)

#### Request
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <s:Header>
        <a:Action xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime
        </a:Action>
        <a:MessageID xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            urn:uuid:12345678-1234-1234-1234-123456789012
        </a:MessageID>
    </s:Header>
    <s:Body>
        <tds:GetSystemDateAndTime/>
    </s:Body>
</s:Envelope>
```

#### Response
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
    <s:Header>
        <a:Action xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTimeResponse
        </a:Action>
        <a:RelatesTo xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            urn:uuid:12345678-1234-1234-1234-123456789012
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

---

### 2. GetDeviceInformation (Requires Authentication)

**Purpose**: Get manufacturer, model, firmware version, etc.

#### Request (with WS-Security)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <s:Header>
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                       xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
                       s:mustUnderstand="1">
            <wsse:UsernameToken>
                <wsse:Username>admin</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">
                    dGVzdFBhc3N3b3JkRGlnZXN0
                </wsse:Password>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
                    MTIzNDU2Nzg5MA==
                </wsse:Nonce>
                <wsu:Created>2024-01-15T14:30:45Z</wsu:Created>
            </wsse:UsernameToken>
        </wsse:Security>
        <a:Action xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation
        </a:Action>
        <a:MessageID xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            urn:uuid:abcdef12-3456-7890-abcd-ef1234567890
        </a:MessageID>
    </s:Header>
    <s:Body>
        <tds:GetDeviceInformation/>
    </s:Body>
</s:Envelope>
```

#### Response
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <s:Header>
        <a:Action xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse
        </a:Action>
        <a:RelatesTo xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            urn:uuid:abcdef12-3456-7890-abcd-ef1234567890
        </a:RelatesTo>
        <a:MessageID xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            urn:uuid:98765432-fedc-ba98-7654-321098765432
        </a:MessageID>
    </s:Header>
    <s:Body>
        <tds:GetDeviceInformationResponse>
            <tds:Manufacturer>Videonetics</tds:Manufacturer>
            <tds:Model>Videonetics_Camera_Emulator</tds:Model>
            <tds:FirmwareVersion>10.0</tds:FirmwareVersion>
            <tds:SerialNumber>1</tds:SerialNumber>
            <tds:HardwareId>1.0</tds:HardwareId>
        </tds:GetDeviceInformationResponse>
    </s:Body>
</s:Envelope>
```

---

### 3. GetServices

**Purpose**: Discover all available ONVIF services on the device

#### Request
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <s:Header>
        <wsse:Security xmlns:wsse="..." s:mustUnderstand="1">
            <!-- WS-Security header -->
        </wsse:Security>
        <a:Action xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            http://www.onvif.org/ver10/device/wsdl/GetServices
        </a:Action>
        <a:MessageID xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            urn:uuid:service-request-001
        </a:MessageID>
    </s:Header>
    <s:Body>
        <tds:GetServices>
            <tds:IncludeCapability>true</tds:IncludeCapability>
        </tds:GetServices>
    </s:Body>
</s:Envelope>
```

#### Response
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
    <s:Header>
        <a:Action s:mustUnderstand="1">
            http://www.onvif.org/ver10/device/wsdl/GetServicesResponse
        </a:Action>
        <a:RelatesTo>urn:uuid:service-request-001</a:RelatesTo>
        <a:MessageID>urn:uuid:service-response-001</a:MessageID>
    </s:Header>
    <s:Body>
        <tds:GetServicesResponse>
            <!-- Device Management Service -->
            <tds:Service>
                <tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace>
                <tds:XAddr>http://192.168.1.100:8080/onvif/device_service</tds:XAddr>
                <tds:Version>
                    <tt:Major>2</tt:Major>
                    <tt:Minor>50</tt:Minor>
                </tds:Version>
            </tds:Service>
            <!-- Media Service -->
            <tds:Service>
                <tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>
                <tds:XAddr>http://192.168.1.100:8080/onvif/media_service</tds:XAddr>
                <tds:Version>
                    <tt:Major>2</tt:Major>
                    <tt:Minor>60</tt:Minor>
                </tds:Version>
            </tds:Service>
        </tds:GetServicesResponse>
    </s:Body>
</s:Envelope>
```

---

### 4. GetCapabilities

**Purpose**: Get device capabilities (services, features)

#### Request
```xml
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <s:Header>
        <!-- Auth header omitted for brevity -->
        <a:Action xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
            http://www.onvif.org/ver10/device/wsdl/GetCapabilities
        </a:Action>
    </s:Header>
    <s:Body>
        <tds:GetCapabilities>
            <tds:Category>All</tds:Category>
        </tds:GetCapabilities>
    </s:Body>
</s:Envelope>
```

#### Response Structure
```xml
<s:Body>
    <tds:GetCapabilitiesResponse>
        <tds:Capabilities>
            <!-- Device capabilities -->
            <tt:Device>
                <tt:XAddr>http://192.168.1.100:8080/onvif/device_service</tt:XAddr>
                <tt:Network>
                    <tt:IPFilter>true</tt:IPFilter>
                    <tt:ZeroConfiguration>true</tt:ZeroConfiguration>
                </tt:Network>
                <tt:System>
                    <tt:DiscoveryResolve>true</tt:DiscoveryResolve>
                    <tt:DiscoveryBye>true</tt:DiscoveryBye>
                </tt:System>
            </tt:Device>
            <!-- Media capabilities -->
            <tt:Media>
                <tt:XAddr>http://192.168.1.100:8080/onvif/media_service</tt:XAddr>
                <tt:StreamingCapabilities>
                    <tt:RTPMulticast>false</tt:RTPMulticast>
                    <tt:RTP_TCP>true</tt:RTP_TCP>
                    <tt:RTP_RTSP_TCP>true</tt:RTP_RTSP_TCP>
                </tt:StreamingCapabilities>
            </tt:Media>
        </tds:Capabilities>
    </tds:GetCapabilitiesResponse>
</s:Body>
```

---

## XML Parsing Techniques

### Simple Tag Extraction (Used in This Project)

From `simpleparser.h`:

```c
uint8_t get_the_tag(
    const char *line,      // Input XML buffer
    const char *tag,       // Tag name (without < >)
    char *out,             // Output buffer
    size_t out_size        // Output buffer size
) {
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    
    // Find opening tag
    const char *start = strstr(line, open);
    if (!start) return 0;
    start += strlen(open);
    
    // Find closing tag
    const char *end = strstr(start, close);
    if (!end) return 0;
    
    // Extract content
    size_t len = end - start;
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    
    return 1;
}
```

### Example Usage
```c
char soap_request[4096];  // Contains XML
char message_id[256];

// Extract <a:MessageID>
if (get_the_tag(soap_request, "a:MessageID", message_id, sizeof(message_id))) {
    printf("MessageID: %s\n", message_id);
}

// Extract username from WS-Security
char username[64];
if (get_the_tag(soap_request, "wsse:Username", username, sizeof(username))) {
    printf("Username: %s\n", username);
}
```

### Parsing Multi-Level Tags

For nested structures like:
```xml
<tds:SystemDateAndTime>
    <tt:UTCDateTime>
        <tt:Time>
            <tt:Hour>14</tt:Hour>
        </tt:Time>
    </tt:UTCDateTime>
</tds:SystemDateAndTime>
```

Parse step-by-step:
```c
char datetime_block[512];
get_the_tag(xml, "tt:UTCDateTime", datetime_block, sizeof(datetime_block));

char time_block[256];
get_the_tag(datetime_block, "tt:Time", time_block, sizeof(time_block));

char hour[8];
get_the_tag(time_block, "tt:Hour", hour, sizeof(hour));
int hour_value = atoi(hour);
```

---

## SOAP Templates in This Project

All templates are defined in `tcp_config.h`. They use `printf`-style format specifiers for dynamic content.

### Template 1: GetSystemDateAndTime Response

```c
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
```

**Format Parameters**:
1. `%s` - Request MessageID (for RelatesTo)
2. `%d` - Hour (0-23)
3. `%d` - Minute (0-59)
4. `%d` - Second (0-59)
5. `%d` - Year (e.g., 2024)
6. `%d` - Month (1-12)
7. `%d` - Day (1-31)

**Usage**:
```c
time_t now = time(NULL);
struct tm *t = gmtime(&now);

char response[2048];
snprintf(response, sizeof(response), GET_DATE_TEMPLATE,
         request_message_id,           // %s
         t->tm_hour, t->tm_min, t->tm_sec,  // %d %d %d
         t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);  // %d %d %d
```

---

### Template 2: GetDeviceInformation Response

```c
const char *GET_DEVICE_INFO_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
    "<s:Header>"
        "<a:Action>http://www.onvif.org/ver10/device/wsdl/GetDeviceInformationResponse</a:Action>"
        "<a:RelatesTo>%s</a:RelatesTo>"
        "<a:MessageID>urn:uuid:%s</a:MessageID>"
    "</s:Header>"
    "<s:Body>"
        "<tds:GetDeviceInformationResponse>"
            "<tds:Manufacturer>%s</tds:Manufacturer>"
            "<tds:Model>%s</tds:Model>"
            "<tds:FirmwareVersion>%s</tds:FirmwareVersion>"
            "<tds:SerialNumber>%s</tds:SerialNumber>"
            "<tds:HardwareId>%s</tds:HardwareId>"
        "</tds:GetDeviceInformationResponse>"
    "</s:Body>"
    "</s:Envelope>";
```

**Format Parameters**:
1. `%s` - Request MessageID (RelatesTo)
2. `%s` - Response UUID
3. `%s` - Manufacturer name
4. `%s` - Model name
5. `%s` - Firmware version
6. `%s` - Serial number
7. `%s` - Hardware ID

**Usage**:
```c
char response_uuid[64];
generate_uuid(response_uuid, sizeof(response_uuid));

char response[2048];
snprintf(response, sizeof(response), GET_DEVICE_INFO_TEMPLATE,
         request_message_id,          // RelatesTo
         response_uuid,                // MessageID
         cfg.manufacturer,             // Manufacturer
         cfg.model,                    // Model
         cfg.firmware_version,         // FirmwareVersion
         cfg.serial_number,            // SerialNumber
         cfg.hardware);                // HardwareId
```

---

### Template 3: GetServices Response

```c
const char *GET_SERVICES_TEMPLATE = 
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" "
    "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
    "<s:Header>"
        "<a:Action s:mustUnderstand=\"1\">"
            "http://www.onvif.org/ver10/device/wsdl/GetServicesResponse"
        "</a:Action>"
        "<a:RelatesTo>%s</a:RelatesTo>"
        "<a:MessageID>urn:uuid:%s</a:MessageID>"
    "</s:Header>"
    "<s:Body>"
        "<tds:GetServicesResponse>"
            "<tds:Service>"
                "<tds:Namespace>http://www.onvif.org/ver10/device/wsdl</tds:Namespace>"
                "<tds:XAddr>http://%s:%d/onvif/device_service</tds:XAddr>"
                "<tds:Version>"
                    "<tt:Major>2</tt:Major>"
                    "<tt:Minor>50</tt:Minor>"
                "</tds:Version>"
            "</tds:Service>"
            "<tds:Service>"
                "<tds:Namespace>http://www.onvif.org/ver10/media/wsdl</tds:Namespace>"
                "<tds:XAddr>http://%s:%d/onvif/media_service</tds:XAddr>"
                "<tds:Version>"
                    "<tt:Major>2</tt:Major>"
                    "<tt:Minor>60</tt:Minor>"
                "</tds:Version>"
            "</tds:Service>"
        "</tds:GetServicesResponse>"
    "</s:Body>"
    "</s:Envelope>";
```

**Format Parameters**:
1. `%s` - Request MessageID (RelatesTo)
2. `%s` - Response UUID
3. `%s` - IP address (for device service)
4. `%d` - Port (for device service)
5. `%s` - IP address (for media service)
6. `%d` - Port (for media service)

---

## Constructing ONVIF Messages

### Step-by-Step: Build GetSystemDateAndTime Response

**Step 1: Extract Request MessageID**
```c
char request_msg_id[256];
get_the_tag(request_buffer, "a:MessageID", request_msg_id, sizeof(request_msg_id));
```

**Step 2: Get Current Time**
```c
time_t now = time(NULL);
struct tm *t = gmtime(&now);  // Get UTC time
```

**Step 3: Fill Template**
```c
char soap_body[2048];
snprintf(soap_body, sizeof(soap_body), GET_DATE_TEMPLATE,
         request_msg_id,                    // %s
         t->tm_hour, t->tm_min, t->tm_sec,  // Hour, Minute, Second
         t->tm_year + 1900,                 // Year (tm_year is years since 1900)
         t->tm_mon + 1,                     // Month (tm_mon is 0-11)
         t->tm_mday);                       // Day
```

**Step 4: Wrap in HTTP Response**
```c
char http_response[4096];
snprintf(http_response, sizeof(http_response),
         "HTTP/1.1 200 OK\r\n"
         "Content-Type: application/soap+xml; charset=utf-8\r\n"
         "Content-Length: %zu\r\n"
         "Connection: close\r\n"
         "\r\n"
         "%s",
         strlen(soap_body), soap_body);
```

**Step 5: Send**
```c
send(client_socket, http_response, strlen(http_response), 0);
```

---

### Building a Request (Client-Side)

```c
// Generate UUID for MessageID
char msg_id[64];
snprintf(msg_id, sizeof(msg_id), "urn:uuid:%ld-%d", time(NULL), rand());

// Build SOAP request
const char *request_template =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
    "<s:Header>"
        "<a:Action xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">"
            "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"
        "</a:Action>"
        "<a:MessageID xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">"
            "%s"
        "</a:MessageID>"
    "</s:Header>"
    "<s:Body>"
        "<tds:GetSystemDateAndTime/>"
    "</s:Body>"
    "</s:Envelope>";

char soap_request[2048];
snprintf(soap_request, sizeof(soap_request), request_template, msg_id);

// Wrap in HTTP POST
char http_request[4096];
snprintf(http_request, sizeof(http_request),
         "POST /onvif/device_service HTTP/1.1\r\n"
         "Host: 192.168.1.100:8080\r\n"
         "Content-Type: application/soap+xml; charset=utf-8\r\n"
         "Content-Length: %zu\r\n"
         "\r\n"
         "%s",
         strlen(soap_request), soap_request);

// Send request
send(socket, http_request, strlen(http_request), 0);
```

---

## Common Pitfalls and Solutions

### 1. Namespace Mismatches

**Problem**: Server expects `xmlns:tds` but client sends `xmlns:onvif`

**Solution**: Always use standard ONVIF namespaces
```xml
<!-- CORRECT -->
xmlns:tds="http://www.onvif.org/ver10/device/wsdl"

<!-- WRONG -->
xmlns:onvif="http://www.onvif.org/ver10/device/wsdl"
```

---

### 2. Missing `RelatesTo` in Response

**Problem**: Client can't match response to request

**Solution**: Always include `<a:RelatesTo>` with request's MessageID
```xml
<s:Header>
    <a:RelatesTo>urn:uuid:12345678-1234-1234-1234-123456789012</a:RelatesTo>
</s:Header>
```

---

### 3. Incorrect Content-Type

**Problem**: HTTP header has wrong content type

**Solution**: Use `application/soap+xml` for SOAP 1.2
```
Content-Type: application/soap+xml; charset=utf-8
```

**Not**: `text/xml` (that's for SOAP 1.1)

---

### 4. Malformed WS-Security Timestamp

**Problem**: Created timestamp not in ISO 8601 format

**Solution**: Use proper format
```c
time_t now = time(NULL);
struct tm *t = gmtime(&now);
char created[32];
strftime(created, sizeof(created), "%Y-%m-%dT%H:%M:%SZ", t);
// Result: "2024-01-15T14:30:45Z"
```

---

### 5. Forgetting XML Declaration

**Problem**: XML parser rejects message

**Solution**: Always start with:
```xml
<?xml version="1.0" encoding="UTF-8"?>
```

---

## Related Documentation

- **[README_ONVIF_AUTHENTICATION.md](README_ONVIF_AUTHENTICATION.md)**: Authentication methods (WS-Security, HTTP Digest)
- **[README_HTTP_HEADERS.md](README_HTTP_HEADERS.md)**: HTTP protocol details
- **[README_MODULAR_DESIGN.md](README_MODULAR_DESIGN.md)**: Project architecture
- **[README_PACKET_ANALYSIS.md](README_PACKET_ANALYSIS.md)**: Network debugging with Wireshark/tcpdump
- **[README_OPENSSL_GUIDE.md](README_OPENSSL_GUIDE.md)**: Cryptographic functions

---

## Quick Reference: Message ID vs RelatesTo

| Field | Direction | Purpose | Format |
|-------|-----------|---------|--------|
| `<a:MessageID>` | Request | Unique request identifier | `urn:uuid:xxxxx` |
| `<a:MessageID>` | Response | Unique response identifier | `urn:uuid:yyyyy` |
| `<a:RelatesTo>` | Response only | Links response to request | Same as request's MessageID |

**Example Flow**:
```
Client → Server:
    <a:MessageID>urn:uuid:12345</a:MessageID>

Server → Client:
    <a:MessageID>urn:uuid:67890</a:MessageID>
    <a:RelatesTo>urn:uuid:12345</a:RelatesTo>
```

---

## Additional Resources

- **ONVIF Core Specification**: https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf
- **SOAP 1.2 Spec**: https://www.w3.org/TR/soap12/
- **WS-Security Spec**: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0.pdf
- **WS-Addressing**: https://www.w3.org/Submission/ws-addressing/

---

**Last Updated**: 2024-01-15  
**Project**: ONVIF Camera Simulator (fakecamera)
