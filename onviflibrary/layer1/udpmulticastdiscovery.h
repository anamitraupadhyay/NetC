// ----- structs-for-udp-multicast-discovery

// ----- xml-req-structure
#include <locale.h>
typedef enum{
    COMMENT_OPEN,
    COMMENT_CLOSED,
    OPEN_TAG,
    CLOSE_TAG,
    OPENING_ENCLOSURE,
    CLOSING_ENCLOSURE, COLON,
}chars;
typedef enum{
    Header,ReplyTo,Address,MessageID, To
}fieldnames;
/*typedef enum{
    isnull,s,a,d
}xmlnstypes;*/
typedef struct{
    //
}xmlns;
typedef struct {
    // null posssible all xmlns a combination set
}envelope;
typedef struct {
    //
    envelope enve;
}xml_req;
typedef enum{
    //
    s,//soap
    tds,//device
    trt,//media
    tptz,//ptz
    timg,//imaging
    tt,//types
    wsse,//auth
    wsu//auth
}namespace_types;