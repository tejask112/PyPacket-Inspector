import struct

from core.utils.NetworkLookupStore import NetworkLookupStore

def parse_dns(payload: bytes) -> dict:
    """
    Parse a DNS message from payload bytes.
    Handles questions and answer/authority/additional resource records.
    """

    if len(payload) < 12:
        raise ValueError(f"Captured DNS Message too short. Expected Minimum Length 12, Got Length {len(payload)}")

    (
        transaction_id,
        flags_raw,
        qd_count,
        an_count, 
        ns_count, 
        ar_count,
    ) = struct.unpack("!HHHHHH", payload[:12])

    flags = _parse_flags(flags_raw)

    offset = 12   
    questions = []
    answers = []
    authorities = []
    additionals = []

    for _ in range(qd_count):
        name, offset = _parse_name(payload, offset)
        qtype, qclass = struct.unpack("!HH", payload[offset:offset + 4])
        offset += 4
        questions.append({
            "name": name,
            "type": NetworkLookupStore.DNS_RECORDS["TYPES"].get(qtype, f"UNKNOWN({qtype})"),
            "class": NetworkLookupStore.DNS_RECORDS["CLASSES"].get(qclass, f"UNKNOWN({qclass})"),
        })

    for _ in range(an_count):
        record, offset = _parse_resource_record(payload, offset)
        answers.append(record)

    for _ in range(ns_count):
        record, offset = _parse_resource_record(payload, offset)
        authorities.append(record)

    for _ in range(ar_count):
        record, offset = _parse_resource_record(payload, offset)
        additionals.append(record)

    return {
        "transaction_id": transaction_id,
        "flags": flags,
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
    }


def _parse_flags(flags_raw: int) -> dict:
    return {
        "qr": (flags_raw >> 15) & 0x1, 
        "opcode": (flags_raw >> 11) & 0xF,
        "aa": bool((flags_raw >> 10) & 0x1), 
        "tc": bool((flags_raw >> 9)  & 0x1), 
        "rd": bool((flags_raw >> 8)  & 0x1),  
        "ra": bool((flags_raw >> 7)  & 0x1), 
        "rcode": flags_raw & 0xF, 
        "is_response": bool((flags_raw >> 15) & 0x1),
    }

def _parse_resource_record(payload: bytes, offset: int) -> tuple[dict, int]:
    name, offset = _parse_name(payload, offset)

    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", payload[offset:offset + 10])
    offset += 10

    rdata_raw = payload[offset:offset + rdlength]
    offset += rdlength

    rdata = _parse_rdata(payload, offset - rdlength, rtype, rdata_raw)

    return {
        "name": name,
        "type": NetworkLookupStore.DNS_RECORDS["TYPES"].get(rtype, f"UNKNOWN({rtype})"),
        "class": NetworkLookupStore.DNS_RECORDS["CLASSES"].get(rclass, f"UNKNOWN({rclass})"),
        "ttl": ttl,
        "rdata": rdata,
    }, offset


def _parse_rdata(payload: bytes, offset: int, rtype: int, rdata_raw: bytes) -> str:

    try:
        if rtype == 1: 
            return f"{rdata_raw[0]}.{rdata_raw[1]}.{rdata_raw[2]}.{rdata_raw[3]}"

        elif rtype == 28:   
            import socket
            return socket.inet_ntop(socket.AF_INET6, rdata_raw)

        elif rtype in (2, 5, 12): 
            name, _ = _parse_name(payload, offset)
            return name

        elif rtype == 15:  
            preference = struct.unpack("!H", rdata_raw[:2])[0]
            exchange, _ = _parse_name(payload, offset + 2)
            return f"{preference} {exchange}"

        elif rtype == 16:   
            strings = []
            i = 0
            while i < len(rdata_raw):
                length = rdata_raw[i]
                i += 1
                strings.append(rdata_raw[i:i + length].decode("utf-8", errors="replace"))
                i += length
            return " ".join(strings)

        elif rtype == 6: 
            mname, offset2 = _parse_name(payload, offset)
            rname, offset2 = _parse_name(payload, offset2)
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", payload[offset2:offset2 + 20])
            return f"{mname} {rname} serial={serial} refresh={refresh} retry={retry} expire={expire} min={minimum}"

        else:
            return rdata_raw.hex()  

    except Exception:
        return rdata_raw.hex()


def _parse_name(payload: bytes, offset: int) -> tuple[str, int]:
    labels = []
    visited_offsets = set() 
    original_offset = offset 

    while True:
        if offset >= len(payload):
            break

        length = payload[offset]

        if length == 0:  
            offset += 1
            break

        elif (length & 0xC0) == 0xC0:  
            if offset + 1 >= len(payload):
                break

            pointer = ((length & 0x3F) << 8) | payload[offset + 1]

            if pointer in visited_offsets:
                break

            visited_offsets.add(pointer)

            if offset == original_offset or original_offset == offset:
                original_offset = offset + 2

            offset = pointer             
        
        else:
            offset += 1
            labels.append(payload[offset:offset + length].decode("utf-8", errors="replace"))
            offset += length

    return ".".join(labels), original_offset if (original_offset != offset) else offset