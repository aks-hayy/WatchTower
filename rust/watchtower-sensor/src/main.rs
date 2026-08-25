use pcap::{Capture, Device, Error as PcapError, Linktype, Offline};
#[allow(dead_code)] // Activated by the aggregate `analyze` command after parity gates.
mod analysis;
#[allow(dead_code)] // Activated atomically with the aggregate analysis command.
mod analysis_wire;
#[allow(dead_code)] // Wired into `analyze` only with the complete frame set.
mod wire;
use std::collections::HashMap;
use std::env;
use std::io::{self, BufWriter, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 4] = b"WT01";
const FRAME_EVENTS: u8 = 1;
const FRAME_HEALTH: u8 = 2;
const FRAME_PACKET_INDEX: u8 = 3;
const FRAME_ANALYSIS_HELLO: u8 = 0x04;
const FRAME_ANALYSIS_WORK: u8 = 0x05;
const FRAME_ANALYSIS_FLOW: u8 = 0x06;
const FRAME_ANALYSIS_CONVERSATION: u8 = 0x07;
const FRAME_ANALYSIS_END: u8 = 0x09;
const FRAME_ANALYSIS_PACKET_INDEX: u8 = 0x0b;
const FRAME_ANALYSIS_PLAN: u8 = 0x10;
const ANALYSIS_CAPABILITY_V1: u64 = (1u64 << 0x04)
    | (1u64 << 0x05)
    | (1u64 << 0x06)
    | (1u64 << 0x07)
    | (1u64 << 0x08)
    | (1u64 << 0x09)
    | (1u64 << 0x0a);
const PACKET_INDEX_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FlowKey { src: String, dst: String, src_port: u16, dst_port: u16, protocol: u8 }

#[derive(Default)]
struct FlowStats { packets: u64, bytes: u64 }

#[derive(Clone, Debug)]
struct Event {
    timestamp: f64, src: String, dst: String, src_port: u16, dst_port: u16,
    protocol: u8, size: u32, flags: u16, raw: Vec<u8>,
}

struct SelectorPacketView<'a> {
    link_class: u8,
    ethertype: u16,
    ip_protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u16,
    icmp_type: Option<u8>,
    payload: &'a [u8],
    frame: &'a [u8],
}

#[derive(Clone, Debug)]
struct PacketIndexRecord {
    packet_ordinal: u64,
    timestamp: f64,
    caplen: u32,
    wirelen: u32,
    link_type: String,
    decoded: bool,
    decode_reason: String,
    src: String,
    dst: String,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: Option<u8>,
    tcp_flags: Option<u16>,
    frame_sha256: [u8; 32],
}

struct CapturedFrame {
    timestamp: f64,
    wirelen: u32,
    raw: Vec<u8>,
}

enum Source { Live(Capture<pcap::Active>), Offline(Capture<Offline>) }

impl Source {
    fn datalink(&self) -> Linktype {
        match self {
            Source::Live(capture) => capture.get_datalink(),
            Source::Offline(capture) => capture.get_datalink(),
        }
    }

    fn next_packet(&mut self) -> Result<Option<CapturedFrame>, PcapError> {
        let result = match self {
            Source::Live(capture) => capture.next_packet(),
            Source::Offline(capture) => capture.next_packet(),
        };
        match result {
            Ok(packet) => Ok(Some(CapturedFrame {
                timestamp: packet.header.ts.tv_sec as f64
                    + packet.header.ts.tv_usec as f64 / 1_000_000.0,
                wirelen: packet.header.len,
                raw: packet.data.to_vec(),
            })),
            Err(PcapError::TimeoutExpired) => Ok(None),
            Err(PcapError::NoMorePackets) => Err(PcapError::NoMorePackets),
            Err(error) => Err(error),
        }
    }
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|item| item == name).and_then(|index| args.get(index + 1)).cloned()
}

fn open_source(args: &[String]) -> Result<Source, String> {
    match args.first().map(String::as_str) {
        Some("capture") => {
            let requested = arg_value(args, "--interface").ok_or("--interface is required")?;
            let device = Device::list().map_err(|error| error.to_string())?.into_iter()
                .find(|item| item.name == requested || item.desc.as_deref() == Some(requested.as_str()))
                .ok_or_else(|| format!("capture device not found: {requested}"))?;
            let inactive = Capture::from_device(device).map_err(|error| error.to_string())?
                .promisc(true).snaplen(65_535).timeout(100).buffer_size(16 * 1024 * 1024).immediate_mode(true);
            let mut active = inactive.open().map_err(|error| error.to_string())?;
            if let Some(filter) = arg_value(args, "--filter") {
                active.filter(&filter, true).map_err(|error| error.to_string())?;
            }
            Ok(Source::Live(active))
        }
        Some("replay") | Some("benchmark") | Some("index") | Some("analyze") => {
            let path = arg_value(args, "--pcap").ok_or("--pcap is required")?;
            Ok(Source::Offline(Capture::from_file(path).map_err(|error| error.to_string())?))
        }
        _ => Err("usage: watchtower-sensor capture --interface NAME | replay --pcap FILE | index --pcap FILE".into()),
    }
}

fn link_type_name(datalink: Linktype) -> String {
    match datalink {
        Linktype::ETHERNET => "ethernet".into(),
        Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => "raw-ip".into(),
        _ => format!("dlt-{}", datalink.0),
    }
}

fn supported_link_type(datalink: Linktype) -> Result<&'static str, String> {
    match datalink {
        Linktype::ETHERNET => Ok("ethernet"),
        Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => Ok("raw-ip"),
        _ => Err(format!("unsupported pcap link type {}", datalink.0)),
    }
}

fn decode_packet(timestamp: f64, raw: Vec<u8>, datalink: Linktype) -> Option<Event> {
    let (mut offset, mut ethertype) = if datalink == Linktype::ETHERNET {
        if raw.len() < 14 { return None; }
        (14usize, u16::from_be_bytes([raw[12], raw[13]]))
    } else {
        let version = raw.first().copied()? >> 4;
        let ethertype = match (datalink, version) {
            (Linktype::IPV4, 4) | (Linktype::RAW, 4) => 0x0800,
            (Linktype::IPV6, 6) | (Linktype::RAW, 6) => 0x86dd,
            _ => return None,
        };
        (0usize, ethertype)
    };
    while datalink == Linktype::ETHERNET && matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if raw.len() < offset + 4 { return None; }
        ethertype = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
        offset += 4;
    }
    let (src, dst, protocol, transport_offset, packet_end) = match ethertype {
        0x0800 => decode_ipv4(&raw, offset).ok()?,
        0x86dd => decode_ipv6(&raw, offset).ok()?,
        0x0806 => {
            let (src, dst, protocol, transport_offset) = decode_arp(&raw, offset)?;
            (src, dst, protocol, transport_offset, raw.len())
        }
        _ => return None,
    };
    if transport_failure_reason(&raw, transport_offset, packet_end, protocol).is_some() {
        return None;
    }
    let (src_port, dst_port, flags) =
        decode_transport(&raw, transport_offset, packet_end, protocol);
    Some(Event {
        timestamp, src, dst, src_port, dst_port, protocol,
        size: raw.len().min(u32::MAX as usize) as u32, flags, raw,
    })
}

fn selector_packet_view(event: &Event, datalink: Linktype) -> Option<SelectorPacketView<'_>> {
    let raw = &event.raw;
    let (mut offset, mut ethertype, link_class) = if datalink == Linktype::ETHERNET {
        if raw.len() < 14 { return None; }
        (14usize, u16::from_be_bytes([raw[12], raw[13]]), 1u8)
    } else {
        let version = raw.first().copied()? >> 4;
        let ethertype = match version {
            4 => 0x0800,
            6 => 0x86dd,
            _ => return None,
        };
        (0usize, ethertype, 2u8)
    };
    while datalink == Linktype::ETHERNET && matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if raw.len() < offset + 4 { return None; }
        ethertype = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
        offset += 4;
    }
    let (protocol, transport_offset, packet_end) = match ethertype {
        0x0800 => {
            let (_, _, protocol, transport, end) = decode_ipv4(raw, offset).ok()?;
            (protocol, transport, end)
        }
        0x86dd => {
            let (_, _, protocol, transport, end) = decode_ipv6(raw, offset).ok()?;
            (protocol, transport, end)
        }
        _ => (event.protocol, raw.len(), raw.len()),
    };
    let payload_offset = match protocol {
        6 if packet_end >= transport_offset + 20 => {
            let header = usize::from((raw[transport_offset + 12] >> 4) & 0x0f) * 4;
            if header < 20 || transport_offset + header > packet_end { packet_end }
            else { transport_offset + header }
        }
        17 if packet_end >= transport_offset + 8 => transport_offset + 8,
        1 | 58 if packet_end >= transport_offset + 8 => transport_offset + 8,
        _ => packet_end,
    };
    Some(SelectorPacketView {
        link_class,
        ethertype,
        ip_protocol: protocol,
        src_port: event.src_port,
        dst_port: event.dst_port,
        tcp_flags: event.flags,
        icmp_type: if matches!(protocol, 1 | 58) && transport_offset < packet_end {
            Some(raw[transport_offset])
        } else { None },
        payload: &raw[payload_offset.min(packet_end)..packet_end],
        frame: raw,
    })
}

fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn selector_clause_matches(
    clause: &wire::SelectorClause,
    packet: &SelectorPacketView<'_>,
) -> bool {
    use wire::SelectorClause::*;
    match clause {
        Always => true,
        LinkClassIn(values) => values.contains(&packet.link_class),
        EtherTypeIn(values) => values.contains(&packet.ethertype),
        IpProtocolIn(values) => values.contains(&packet.ip_protocol),
        EitherPortIn(values) => values.contains(&packet.src_port) || values.contains(&packet.dst_port),
        SourcePortIn(values) => values.contains(&packet.src_port),
        DestinationPortIn(values) => values.contains(&packet.dst_port),
        TcpFlags { required, forbidden } => {
            packet.ip_protocol == 6
                && packet.tcp_flags & required == *required
                && packet.tcp_flags & forbidden == 0
        }
        IcmpTypeIn(values) => packet.icmp_type.is_some_and(|value| values.contains(&value)),
        PayloadMinimumLength(length) => packet.payload.len() >= *length as usize,
        PayloadPrefixIn(values) => values.iter().any(|value| packet.payload.starts_with(value)),
        PayloadContainsAny(values) => values.iter().any(|value| contains_slice(packet.payload, value)),
        PayloadByteMask { offset, mask, expected } => packet.payload.get(*offset as usize)
            .is_some_and(|value| value & mask == *expected),
        PayloadDiversity { sample, minimum_distinct } => {
            let mut seen = [false; 256];
            let mut count = 0u16;
            for value in packet.payload.iter().take(*sample as usize) {
                if !seen[*value as usize] {
                    seen[*value as usize] = true;
                    count += 1;
                }
            }
            count >= *minimum_distinct
        }
        FrameWindowContainsAny { start, end, literals } => {
            let start = (*start as usize).min(packet.frame.len());
            let end = (*end as usize).min(packet.frame.len());
            start <= end && literals.iter().any(|value| contains_slice(&packet.frame[start..end], value))
        }
    }
}

fn select_candidate(plan: &wire::AnalysisPlan, event: &Event, datalink: Linktype) -> (u8, u64) {
    if plan.selector_programs.is_empty() {
        return (2, 0);
    }
    let Some(packet) = selector_packet_view(event, datalink) else { return (0, 0); };
    let mut mode = 0u8;
    let mut matched = 0u64;
    for program in &plan.selector_programs {
        if program.clauses.iter().all(|clause| selector_clause_matches(clause, &packet)) {
            mode = mode.max(program.candidate_mode);
            matched |= 1u64 << program.program_id;
        }
    }
    (mode, matched)
}

fn decode_arp(raw: &[u8], offset: usize) -> Option<(String, String, u8, usize)> {
    if raw.len() < offset + 28 || raw[offset + 4] != 6 || raw[offset + 5] != 4 {
        return None;
    }
    let src = Ipv4Addr::new(raw[offset + 14], raw[offset + 15], raw[offset + 16], raw[offset + 17]);
    let dst = Ipv4Addr::new(raw[offset + 24], raw[offset + 25], raw[offset + 26], raw[offset + 27]);
    Some((src.to_string(), dst.to_string(), 254, raw.len()))
}

fn decode_ipv4(
    raw: &[u8],
    offset: usize,
) -> Result<(String, String, u8, usize, usize), &'static str> {
    if raw.len() < offset + 20 {
        return Err("truncated_ipv4");
    }
    if raw[offset] >> 4 != 4 {
        return Err("malformed_ipv4");
    }
    let header_len = ((raw[offset] & 0x0f) as usize) * 4;
    if header_len < 20 {
        return Err("malformed_ipv4");
    }
    if raw.len() < offset + header_len {
        return Err("truncated_ipv4");
    }
    let total_len = usize::from(u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]));
    if total_len < header_len {
        return Err("malformed_ipv4_length");
    }
    let packet_end = offset.checked_add(total_len).ok_or("malformed_ipv4_length")?;
    if packet_end > raw.len() {
        return Err("truncated_ipv4");
    }
    let fragment = u16::from_be_bytes([raw[offset + 6], raw[offset + 7]]);
    if fragment & 0x3fff != 0 {
        return Err("fragmented_ipv4");
    }
    let src = Ipv4Addr::new(raw[offset + 12], raw[offset + 13], raw[offset + 14], raw[offset + 15]);
    let dst = Ipv4Addr::new(raw[offset + 16], raw[offset + 17], raw[offset + 18], raw[offset + 19]);
    Ok((
        src.to_string(),
        dst.to_string(),
        raw[offset + 9],
        offset + header_len,
        packet_end,
    ))
}

fn decode_ipv6(
    raw: &[u8],
    offset: usize,
) -> Result<(String, String, u8, usize, usize), &'static str> {
    if raw.len() < offset + 40 {
        return Err("truncated_ipv6");
    }
    if raw[offset] >> 4 != 6 {
        return Err("malformed_ipv6");
    }
    let src: [u8; 16] = raw[offset + 8..offset + 24]
        .try_into()
        .map_err(|_| "malformed_ipv6")?;
    let dst: [u8; 16] = raw[offset + 24..offset + 40]
        .try_into()
        .map_err(|_| "malformed_ipv6")?;
    let payload_len = usize::from(u16::from_be_bytes([raw[offset + 4], raw[offset + 5]]));
    let packet_end = offset
        .checked_add(40)
        .and_then(|value| value.checked_add(payload_len))
        .ok_or("malformed_ipv6_length")?;
    if packet_end > raw.len() {
        return Err("truncated_ipv6");
    }
    let mut next = raw[offset + 6];
    let mut cursor = offset + 40;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                if packet_end < cursor + 2 {
                    return Err("truncated_ipv6_extension");
                }
                let length = (raw[cursor + 1] as usize + 1) * 8;
                next = raw[cursor];
                cursor = cursor
                    .checked_add(length)
                    .ok_or("malformed_ipv6_length")?;
            }
            44 => {
                if packet_end < cursor + 8 {
                    return Err("truncated_ipv6_extension");
                }
                let fragment = u16::from_be_bytes([raw[cursor + 2], raw[cursor + 3]]);
                if fragment != 0 {
                    return Err("fragmented_ipv6");
                }
                next = raw[cursor];
                cursor += 8;
            }
            51 => {
                if packet_end < cursor + 2 {
                    return Err("truncated_ipv6_extension");
                }
                let length = (raw[cursor + 1] as usize + 2) * 4;
                next = raw[cursor];
                cursor = cursor
                    .checked_add(length)
                    .ok_or("malformed_ipv6_length")?;
            }
            _ => break,
        }
        if cursor > packet_end {
            return Err("truncated_ipv6_extension");
        }
    }
    if matches!(next, 0 | 43 | 44 | 51 | 60) {
        return Err("too_many_ipv6_extensions");
    }
    Ok((
        Ipv6Addr::from(src).to_string(),
        Ipv6Addr::from(dst).to_string(),
        next,
        cursor,
        packet_end,
    ))
}

fn transport_failure_reason(
    raw: &[u8],
    offset: usize,
    packet_end: usize,
    protocol: u8,
) -> Option<&'static str> {
    let available = packet_end.checked_sub(offset)?;
    match protocol {
        6 => {
            if available < 20 || raw.len() < offset + 20 {
                return Some("truncated_tcp");
            }
            let header_len = usize::from(raw[offset + 12] >> 4) * 4;
            if header_len < 20 {
                return Some("malformed_tcp");
            }
            if header_len > available || raw.len() < offset + header_len {
                return Some("truncated_tcp");
            }
        }
        17 => {
            if available < 8 || raw.len() < offset + 8 {
                return Some("truncated_udp");
            }
            let udp_len = usize::from(u16::from_be_bytes([raw[offset + 4], raw[offset + 5]]));
            if udp_len < 8 {
                return Some("malformed_udp");
            }
            if udp_len > available {
                return Some("truncated_udp");
            }
        }
        _ => {}
    }
    None
}

fn decode_transport(
    raw: &[u8],
    offset: usize,
    packet_end: usize,
    protocol: u8,
) -> (u16, u16, u16) {
    if packet_end < offset + 4 || raw.len() < offset + 4 {
        return (0, 0, 0);
    }
    let src_port = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
    let dst_port = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
    let flags = if protocol == 6 && packet_end >= offset + 14 && raw.len() >= offset + 14 {
        u16::from(raw[offset + 13])
    } else {
        0
    };
    if protocol == 6 || protocol == 17 { (src_port, dst_port, flags) } else { (0, 0, 0) }
}

fn decode_failure_reason(raw: &[u8], datalink: Linktype) -> String {
    if datalink == Linktype::ETHERNET {
        if raw.len() < 14 {
            return "truncated_ethernet".into();
        }
        let mut offset = 14usize;
        let mut ethertype = u16::from_be_bytes([raw[12], raw[13]]);
        while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
            if raw.len() < offset + 4 {
                return "truncated_vlan".into();
            }
            ethertype = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
            offset += 4;
        }
        return match ethertype {
            0x0800 => "malformed_ipv4",
            0x86dd => "malformed_ipv6",
            0x0806 => "malformed_arp",
            _ => "unsupported_ethertype",
        }.into();
    }
    if matches!(datalink, Linktype::RAW | Linktype::IPV4 | Linktype::IPV6) {
        return if raw.is_empty() {
            "truncated_ip"
        } else {
            "malformed_ip"
        }.into();
    }
    "unsupported_link_type".into()
}

fn truncated_transport_reason(raw: &[u8], datalink: Linktype) -> Option<&'static str> {
    let (mut offset, mut ethertype) = if datalink == Linktype::ETHERNET {
        if raw.len() < 14 {
            return None;
        }
        (14usize, u16::from_be_bytes([raw[12], raw[13]]))
    } else {
        let version = raw.first().copied()? >> 4;
        let ethertype = match (datalink, version) {
            (Linktype::IPV4, 4) | (Linktype::RAW, 4) => 0x0800,
            (Linktype::IPV6, 6) | (Linktype::RAW, 6) => 0x86dd,
            _ => return None,
        };
        (0usize, ethertype)
    };
    while datalink == Linktype::ETHERNET && matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if raw.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
        offset += 4;
    }
    let (protocol, transport_offset, packet_end) = match ethertype {
        0x0800 => match decode_ipv4(raw, offset) {
            Ok((_, _, protocol, transport_offset, packet_end)) => {
                (protocol, transport_offset, packet_end)
            }
            Err(reason) => return Some(reason),
        },
        0x86dd => match decode_ipv6(raw, offset) {
            Ok((_, _, protocol, transport_offset, packet_end)) => {
                (protocol, transport_offset, packet_end)
            }
            Err(reason) => return Some(reason),
        },
        _ => return None,
    };
    transport_failure_reason(raw, transport_offset, packet_end, protocol)
}

fn packet_index_record(
    packet_ordinal: u64,
    timestamp: f64,
    raw: Vec<u8>,
    wirelen: u32,
    datalink: Linktype,
) -> PacketIndexRecord {
    let caplen = raw.len().min(u32::MAX as usize) as u32;
    let frame_sha256 = sha256(&raw);
    let link_type = link_type_name(datalink);
    let failure_reason = decode_failure_reason(&raw, datalink);
    if let Some(reason) = truncated_transport_reason(&raw, datalink) {
        return PacketIndexRecord {
            packet_ordinal,
            timestamp,
            caplen,
            wirelen,
            link_type,
            decoded: false,
            decode_reason: reason.into(),
            src: String::new(),
            dst: String::new(),
            src_port: None,
            dst_port: None,
            protocol: None,
            tcp_flags: None,
            frame_sha256,
        };
    }
    match decode_packet(timestamp, raw, datalink) {
        Some(event) => {
            let has_ports = event.protocol == 6 || event.protocol == 17;
            PacketIndexRecord {
                packet_ordinal,
                timestamp,
                caplen,
                wirelen,
                link_type,
                decoded: true,
                decode_reason: String::new(),
                src: event.src,
                dst: event.dst,
                src_port: has_ports.then_some(event.src_port),
                dst_port: has_ports.then_some(event.dst_port),
                protocol: Some(event.protocol),
                tcp_flags: (event.protocol == 6).then_some(event.flags),
                frame_sha256,
            }
        }
        None => PacketIndexRecord {
            packet_ordinal,
            timestamp,
            caplen,
            wirelen,
            link_type,
            decoded: false,
            decode_reason: failure_reason,
            src: String::new(),
            dst: String::new(),
            src_port: None,
            dst_port: None,
            protocol: None,
            tcp_flags: None,
            frame_sha256,
        },
    }
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut state = [
        0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(bytes.try_into().expect("four-byte word"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut work = state;
        for index in 0..64 {
            let sum1 = work[4].rotate_right(6)
                ^ work[4].rotate_right(11)
                ^ work[4].rotate_right(25);
            let choice = (work[4] & work[5]) ^ ((!work[4]) & work[6]);
            let temp1 = work[7]
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = work[0].rotate_right(2)
                ^ work[0].rotate_right(13)
                ^ work[0].rotate_right(22);
            let majority = (work[0] & work[1]) ^ (work[0] & work[2]) ^ (work[1] & work[2]);
            let temp2 = sum0.wrapping_add(majority);
            work = [
                temp1.wrapping_add(temp2),
                work[0],
                work[1],
                work[2],
                work[3].wrapping_add(temp1),
                work[4],
                work[5],
                work[6],
            ];
        }
        for index in 0..8 {
            state[index] = state[index].wrapping_add(work[index]);
        }
    }
    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

#[cfg(test)]
fn hex_sha256(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn encode_short_string(payload: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let length = bytes.len().min(u8::MAX as usize);
    payload.push(length as u8);
    payload.extend_from_slice(&bytes[..length]);
}

fn encode_packet_index(records: &[PacketIndexRecord]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(PACKET_INDEX_SCHEMA_VERSION);
    payload.extend_from_slice(&(records.len() as u16).to_be_bytes());
    for record in records {
        payload.extend_from_slice(&record.packet_ordinal.to_be_bytes());
        payload.extend_from_slice(&record.timestamp.to_be_bytes());
        payload.extend_from_slice(&record.caplen.to_be_bytes());
        payload.extend_from_slice(&record.wirelen.to_be_bytes());
        encode_short_string(&mut payload, &record.link_type);
        payload.push(u8::from(record.decoded));
        encode_short_string(&mut payload, &record.decode_reason);
        encode_short_string(&mut payload, &record.src);
        encode_short_string(&mut payload, &record.dst);
        let presence = u8::from(record.src_port.is_some())
            | (u8::from(record.dst_port.is_some()) << 1)
            | (u8::from(record.protocol.is_some()) << 2)
            | (u8::from(record.tcp_flags.is_some()) << 3);
        payload.push(presence);
        payload.extend_from_slice(&record.src_port.unwrap_or_default().to_be_bytes());
        payload.extend_from_slice(&record.dst_port.unwrap_or_default().to_be_bytes());
        payload.push(record.protocol.unwrap_or_default());
        payload.extend_from_slice(&record.tcp_flags.unwrap_or_default().to_be_bytes());
        payload.extend_from_slice(&record.frame_sha256);
    }
    payload
}

fn write_frame(kind: u8, payload: &[u8]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    write_frame_to(&mut handle, kind, payload)?;
    handle.flush()
}

fn write_frame_to<W: Write>(writer: &mut W, kind: u8, payload: &[u8]) -> io::Result<()> {
    writer.write_all(MAGIC)?;
    writer.write_all(&[1, kind])?;
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)
}

fn encode_events(events: &[Event]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(events.len() as u16).to_be_bytes());
    for event in events {
        payload.extend_from_slice(&event.timestamp.to_be_bytes());
        payload.push(event.src.len().min(255) as u8); payload.extend_from_slice(event.src.as_bytes());
        payload.push(event.dst.len().min(255) as u8); payload.extend_from_slice(event.dst.as_bytes());
        payload.extend_from_slice(&event.src_port.to_be_bytes());
        payload.extend_from_slice(&event.dst_port.to_be_bytes()); payload.push(event.protocol);
        payload.extend_from_slice(&event.size.to_be_bytes()); payload.extend_from_slice(&event.flags.to_be_bytes());
        payload.extend_from_slice(&(event.raw.len() as u32).to_be_bytes()); payload.extend_from_slice(&event.raw);
    }
    payload
}

fn encode_health(received: u64, emitted: u64, flows: usize, started: Instant, link_type: &str) -> Vec<u8> {
    format!("{{\"status\":\"ready\",\"link_type\":\"{link_type}\",\"received_packets\":{received},\"emitted_packets\":{emitted},\"flows\":{flows},\"uptime_ms\":{}}}", started.elapsed().as_millis()).into_bytes()
}

fn run_packet_index(
    mut source: Source,
    datalink: Linktype,
    batch_size: usize,
) -> Result<(), String> {
    let mut batch = Vec::with_capacity(batch_size);
    let mut packet_ordinal = 0u64;
    loop {
        match source.next_packet() {
            Ok(Some(frame)) => {
                packet_ordinal = packet_ordinal
                    .checked_add(1)
                    .ok_or("packet ordinal overflow")?;
                batch.push(packet_index_record(
                    packet_ordinal,
                    frame.timestamp,
                    frame.raw,
                    frame.wirelen,
                    datalink,
                ));
                if batch.len() >= batch_size {
                    write_frame(FRAME_PACKET_INDEX, &encode_packet_index(&batch))
                        .map_err(|error| error.to_string())?;
                    batch.clear();
                }
            }
            Ok(None) => {}
            Err(PcapError::NoMorePackets) => break,
            Err(error) => return Err(error.to_string()),
        }
    }
    if !batch.is_empty() {
        write_frame(FRAME_PACKET_INDEX, &encode_packet_index(&batch))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn read_analysis_plan() -> Result<wire::AnalysisPlan, String> {
    let mut input = io::stdin().lock();
    let mut header = [0u8; 10];
    input.read_exact(&mut header).map_err(|error| format!("analysis plan header: {error}"))?;
    if &header[..4] != MAGIC || header[4] != 1 || header[5] != FRAME_ANALYSIS_PLAN {
        return Err("first analysis input frame must be a WT01 analysis plan".into());
    }
    let size = u32::from_be_bytes(header[6..10].try_into().expect("four bytes")) as usize;
    if size > 1024 * 1024 {
        return Err("analysis plan frame exceeds 1048576 bytes".into());
    }
    let mut payload = vec![0u8; size];
    input.read_exact(&mut payload).map_err(|error| format!("analysis plan payload: {error}"))?;
    wire::decode_analysis_plan(&payload)
}

fn update_frame_digest(current: [u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut value = Vec::with_capacity(32 + payload.len());
    value.extend_from_slice(&current);
    value.extend_from_slice(payload);
    sha256(&value)
}

fn run_analysis(args: &[String]) -> Result<(), String> {
    let plan = read_analysis_plan()?;
    if plan.execution_mode != 1 {
        return Err("aggregate analyze requires execution mode aggregate-v1".into());
    }
    let mut source = open_source(args)?;
    let datalink = source.datalink();
    let link_type = supported_link_type(datalink)?;
    let stdout = io::stdout();
    let mut writer = BufWriter::with_capacity(
        usize::try_from(plan.target_batch_bytes).unwrap_or(1024 * 1024),
        stdout.lock(),
    );
    let hello = wire::encode_analysis_hello(
        &plan,
        env!("CARGO_PKG_VERSION"),
        datalink.0,
        link_type,
        ANALYSIS_CAPABILITY_V1,
    )?;
    write_frame_to(&mut writer, FRAME_ANALYSIS_HELLO, &hello).map_err(|error| error.to_string())?;
    writer.flush().map_err(|error| error.to_string())?;

    let mut state = analysis::AnalysisState::with_sample_byte_limit(
        usize::from(plan.max_flow_samples),
        plan.max_directional_flows as usize,
        plan.max_active_conversations as usize,
        plan.max_resume_conversations as usize,
        plan.max_endpoints as usize,
        plan.max_flow_sample_bytes,
    );
    let started = Instant::now();
    let mut read_decode_ns = 0u64;
    let mut candidate_match_ns = 0u64;
    let mut aggregate_ns = 0u64;
    let mut blocked_write_ns = 0u64;
    let mut packet_ordinal = 0u64;
    let mut decoded_items = 0u64;
    let mut raw_candidate_bytes = 0u64;
    let mut first_timestamp: Option<f64> = None;
    let mut last_timestamp: Option<f64> = None;
    let mut endpoint_high = 0u32;
    let mut flow_high = 0u32;
    let mut conversation_high = 0u32;
    let mut resume_high = 0u32;
    let mut sample_bytes_high = 0u64;
    let mut sequence = 0u32;
    let mut index_batch = Vec::with_capacity(4096);
    let mut digests = [[0u8; 32]; 5];
    let mut terminal_status = 1u8;
    let mut error_code = String::new();

    loop {
        let read_started = Instant::now();
        let frame = match source.next_packet() {
            Ok(Some(frame)) => frame,
            Ok(None) => continue,
            Err(PcapError::NoMorePackets) => break,
            Err(error) => {
                terminal_status = 2;
                error_code = format!("pcap_read:{error}");
                break;
            }
        };
        packet_ordinal = packet_ordinal.checked_add(1).ok_or("packet ordinal overflow")?;
        let index = packet_index_record(
            packet_ordinal,
            frame.timestamp,
            frame.raw.clone(),
            frame.wirelen,
            datalink,
        );
        let decoded = decode_packet(frame.timestamp, frame.raw, datalink);
        read_decode_ns = read_decode_ns.saturating_add(
            read_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
        );
        index_batch.push(index);
        if index_batch.len() >= 4096 {
            let payload = encode_packet_index(&index_batch);
            let write_started = Instant::now();
            write_frame_to(&mut writer, FRAME_ANALYSIS_PACKET_INDEX, &payload)
                .map_err(|error| error.to_string())?;
            blocked_write_ns = blocked_write_ns.saturating_add(
                write_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
            );
            digests[0] = update_frame_digest(digests[0], &payload);
            index_batch.clear();
        }
        let Some(event) = decoded else { continue; };
        first_timestamp = Some(first_timestamp.map_or(event.timestamp, |value| value.min(event.timestamp)));
        last_timestamp = Some(last_timestamp.map_or(event.timestamp, |value| value.max(event.timestamp)));
        let candidate_started = Instant::now();
        let (mut candidate_mode, matched_programs) = select_candidate(&plan, &event, datalink);
        candidate_match_ns = candidate_match_ns.saturating_add(
            candidate_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
        );
        let aggregate_started = Instant::now();
        let analysis_event = analysis::AnalysisEvent {
            timestamp: event.timestamp,
            src: event.src.clone(),
            dst: event.dst.clone(),
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol,
            size: event.size,
            tcp_flags: event.flags,
        };
        let observation = match state.observe(analysis_event.clone()) {
            Ok(value) => value,
            Err(error) => {
                terminal_status = 2;
                error_code = format!("aggregate_capacity:{error}");
                break;
            }
        };
        aggregate_ns = aggregate_ns.saturating_add(
            aggregate_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
        );
        if candidate_mode == 0 && (
            !observation.endpoint_definitions.is_empty()
                || observation.flow_definition.is_some()
                || observation.conversation_definition.is_some()
        ) {
            candidate_mode = 1;
        }
        if candidate_mode == 0 {
            continue;
        }
        decoded_items += 1;
        raw_candidate_bytes = raw_candidate_bytes.saturating_add(event.raw.len() as u64);
        endpoint_high = endpoint_high.max(state.endpoint_count() as u32);
        flow_high = flow_high.max(state.directional_flow_count() as u32);
        conversation_high = conversation_high.max(state.active_conversation_count() as u32);
        resume_high = resume_high.max(state.resume_conversation_count() as u32);
        sample_bytes_high = sample_bytes_high.max(state.sample_bytes());
        sequence = sequence.checked_add(1).ok_or("analysis sequence overflow")?;
        let payload = analysis_wire::encode_work_item(
            sequence,
            packet_ordinal,
            &analysis_event,
            &observation,
            &event.raw,
            candidate_mode,
            matched_programs,
        )?;
        let write_started = Instant::now();
        write_frame_to(&mut writer, FRAME_ANALYSIS_WORK, &payload)
            .map_err(|error| error.to_string())?;
        blocked_write_ns = blocked_write_ns.saturating_add(
            write_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
        );
        digests[1] = update_frame_digest(digests[1], &payload);
    }

    if !index_batch.is_empty() {
        let payload = encode_packet_index(&index_batch);
        write_frame_to(&mut writer, FRAME_ANALYSIS_PACKET_INDEX, &payload)
            .map_err(|error| error.to_string())?;
        digests[0] = update_frame_digest(digests[0], &payload);
    }
    let flow_records = state.directional_flow_records();
    for records in flow_records.chunks(4096) {
        sequence = sequence.checked_add(1).ok_or("analysis sequence overflow")?;
        let payload = analysis_wire::encode_flow_batch(sequence, records)?;
        write_frame_to(&mut writer, FRAME_ANALYSIS_FLOW, &payload)
            .map_err(|error| error.to_string())?;
        digests[2] = update_frame_digest(digests[2], &payload);
    }
    let conversation_records = state.conversation_records();
    for records in conversation_records.chunks(4096) {
        sequence = sequence.checked_add(1).ok_or("analysis sequence overflow")?;
        let payload = analysis_wire::encode_conversation_batch(sequence, records)?;
        write_frame_to(&mut writer, FRAME_ANALYSIS_CONVERSATION, &payload)
            .map_err(|error| error.to_string())?;
        digests[3] = update_frame_digest(digests[3], &payload);
    }
    let end = wire::AnalysisEnd {
        plan_sha256: plan.plan_sha256,
        terminal_status,
        error_code,
        counters: [
            packet_ordinal,
            decoded_items,
            decoded_items,
            raw_candidate_bytes,
            decoded_items,
            flow_records.len() as u64,
            decoded_items,
            conversation_records.len() as u64,
            0,
            0,
            0,
            0,
        ],
        first_decoded_timestamp: first_timestamp,
        last_decoded_timestamp: last_timestamp,
        digests,
        timers_ns: [read_decode_ns, candidate_match_ns, aggregate_ns, blocked_write_ns],
        high_waters: [endpoint_high, flow_high, conversation_high, resume_high],
        sample_bytes_high_water: sample_bytes_high,
    };
    let payload = wire::encode_analysis_end(&end)?;
    write_frame_to(&mut writer, FRAME_ANALYSIS_END, &payload).map_err(|error| error.to_string())?;
    writer.flush().map_err(|error| error.to_string())?;
    let _ = started;
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("--version") {
        println!("watchtower-sensor {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("list") {
        for device in Device::list().map_err(|error| error.to_string())? {
            println!("{}\t{}", device.name, device.desc.unwrap_or_default());
        }
        return Ok(());
    }
    let command = args.first().map(String::as_str);
    if command == Some("analyze") {
        return run_analysis(args);
    }
    let benchmark = command == Some("benchmark");
    let index = command == Some("index");
    let batch_size = arg_value(args, "--batch").and_then(|value| value.parse().ok()).unwrap_or(256usize).clamp(1, 4096);
    let mut source = open_source(args)?;
    let datalink = source.datalink();
    if index {
        return run_packet_index(source, datalink, batch_size);
    }
    let link_type = supported_link_type(datalink)?;
    let mut batch = Vec::with_capacity(batch_size);
    let mut flows: HashMap<FlowKey, FlowStats> = HashMap::new();
    let (mut received, mut emitted) = (0u64, 0u64);
    let started = Instant::now();
    let mut last_health = Instant::now();
    if !benchmark {
        write_frame(FRAME_HEALTH, &encode_health(0, 0, 0, started, link_type)).map_err(|error| error.to_string())?;
    }
    loop {
        match source.next_packet() {
            Ok(Some(frame)) => {
                received += 1;
                if let Some(event) = decode_packet(frame.timestamp, frame.raw, datalink) {
                    let key = FlowKey { src: event.src.clone(), dst: event.dst.clone(), src_port: event.src_port, dst_port: event.dst_port, protocol: event.protocol };
                    let stats = flows.entry(key).or_default(); stats.packets += 1; stats.bytes += u64::from(event.size);
                    batch.push(event);
                    if batch.len() >= batch_size {
                        if !benchmark { write_frame(FRAME_EVENTS, &encode_events(&batch)).map_err(|error| error.to_string())?; }
                        emitted += batch.len() as u64; batch.clear();
                    }
                }
            }
            Ok(None) => {}
            Err(PcapError::NoMorePackets) => break,
            Err(error) => return Err(error.to_string()),
        }
        if !benchmark && last_health.elapsed() >= Duration::from_secs(1) {
            write_frame(FRAME_HEALTH, &encode_health(received, emitted, flows.len(), started, link_type)).map_err(|error| error.to_string())?;
            last_health = Instant::now();
        }
    }
    if !batch.is_empty() {
        if !benchmark { write_frame(FRAME_EVENTS, &encode_events(&batch)).map_err(|error| error.to_string())?; }
        emitted += batch.len() as u64;
    }
    if benchmark {
        let elapsed = started.elapsed().as_secs_f64().max(0.000_001);
        println!("packets={received} events={emitted} flows={} seconds={elapsed:.6} pps={:.0}", flows.len(), received as f64 / elapsed);
    } else {
        write_frame(FRAME_HEALTH, &encode_health(received, emitted, flows.len(), started, link_type)).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        eprintln!("watchtower-sensor error at {now}: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_plan_wire_rejects_tampering_after_structural_validation() {
        let payload = wire::test_plan_payload();
        let plan = wire::decode_analysis_plan(&payload).expect("valid plan");
        assert_eq!(plan.execution_mode, 1);
        assert_eq!(plan.target_batch_bytes, 1024 * 1024);
        assert_eq!(plan.max_active_conversations, 100_000);
        assert_eq!(plan.max_resume_conversations, 100_000);
        assert_eq!(plan.max_directional_flows, 220_000);
        assert_eq!(plan.max_flow_samples, 500);

        let mut tampered = payload;
        tampered[65] = 99;
        assert!(wire::decode_analysis_plan(&tampered)
            .expect_err("unknown mode must be rejected")
            .contains("execution mode"));
    }

    fn ipv4_tcp_packet(vlan: bool) -> Vec<u8> {
        let vlan_len = if vlan { 4 } else { 0 };
        let mut packet = vec![0u8; 14 + vlan_len + 20 + 20];
        if vlan {
            packet[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
            packet[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        } else {
            packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        }
        let ip = 14 + vlan_len;
        packet[ip] = 0x45;
        packet[ip + 2..ip + 4].copy_from_slice(&40u16.to_be_bytes());
        packet[ip + 9] = 6;
        packet[ip + 12..ip + 16].copy_from_slice(&[10, 0, 0, 1]);
        packet[ip + 16..ip + 20].copy_from_slice(&[10, 0, 0, 2]);
        let tcp = ip + 20;
        packet[tcp..tcp + 2].copy_from_slice(&12345u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
        packet[tcp + 12] = 5 << 4;
        packet[tcp + 13] = 0x12;
        packet
    }

    #[test]
    fn decodes_vlan_ipv4_tcp() {
        let packet = ipv4_tcp_packet(true);
        let event = decode_packet(1.0, packet, Linktype::ETHERNET).unwrap();
        assert_eq!(event.src, "10.0.0.1"); assert_eq!(event.dst_port, 443); assert_eq!(event.flags, 0x12);
    }
    #[test]
    fn rejects_truncated_frames() {
        assert!(decode_packet(1.0, vec![0u8; 10], Linktype::ETHERNET).is_none());
    }

    #[test]
    fn decodes_raw_ipv4_udp() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..22].copy_from_slice(&53000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());
        let event = decode_packet(1.0, packet, Linktype::IPV4).unwrap();
        assert_eq!(event.src, "10.0.0.1");
        assert_eq!(event.dst_port, 53);
    }

    #[test]
    fn packet_index_normalizes_ethernet_and_vlan_rows() {
        for packet in [ipv4_tcp_packet(false), ipv4_tcp_packet(true)] {
            let record = packet_index_record(
                7,
                1.5,
                packet.clone(),
                packet.len() as u32 + 4,
                Linktype::ETHERNET,
            );
            assert_eq!(record.packet_ordinal, 7);
            assert_eq!(record.timestamp, 1.5);
            assert_eq!(record.caplen, packet.len() as u32);
            assert_eq!(record.wirelen, packet.len() as u32 + 4);
            assert_eq!(record.link_type, "ethernet");
            assert!(record.decoded);
            assert_eq!(record.decode_reason, "");
            assert_eq!(record.src, "10.0.0.1");
            assert_eq!(record.dst, "10.0.0.2");
            assert_eq!(record.src_port, Some(12345));
            assert_eq!(record.dst_port, Some(443));
            assert_eq!(record.protocol, Some(6));
            assert_eq!(record.tcp_flags, Some(0x12));
            assert_eq!(record.frame_sha256.len(), 32);
        }
    }

    #[test]
    fn packet_index_normalizes_raw_ipv4_rows() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&53000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());

        let record = packet_index_record(1, 2.25, packet, 28, Linktype::IPV4);

        assert!(record.decoded);
        assert_eq!(record.link_type, "raw-ip");
        assert_eq!(record.src, "192.0.2.1");
        assert_eq!(record.dst, "198.51.100.2");
        assert_eq!(record.src_port, Some(53000));
        assert_eq!(record.dst_port, Some(53));
        assert_eq!(record.protocol, Some(17));
        assert_eq!(record.tcp_flags, None);
    }

    #[test]
    fn packet_index_preserves_undecodable_frames_without_raw_payloads() {
        let raw = b"abc".to_vec();
        let record = packet_index_record(3, 9.0, raw.clone(), 60, Linktype::ETHERNET);

        assert!(!record.decoded);
        assert_eq!(record.decode_reason, "truncated_ethernet");
        assert_eq!(
            hex_sha256(&record.frame_sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );

        let payload = encode_packet_index(&[record]);
        assert_eq!(payload[0], 1);
        assert_eq!(&payload[1..3], &1u16.to_be_bytes());
        assert!(!payload.windows(raw.len()).any(|window| window == raw));
    }

    #[test]
    fn sha256_matches_standard_padding_and_multiblock_vectors() {
        assert_eq!(
            hex_sha256(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            hex_sha256(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        );
        assert_eq!(
            hex_sha256(&sha256(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        );
    }

    #[test]
    fn packet_index_marks_truncated_transport_headers_undecodable() {
        let mut packet = vec![0u8; 14 + 20];
        packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&20u16.to_be_bytes());
        packet[23] = 6;
        packet[26..30].copy_from_slice(&[10, 0, 0, 1]);
        packet[30..34].copy_from_slice(&[10, 0, 0, 2]);

        let record = packet_index_record(
            4,
            10.0,
            packet.clone(),
            packet.len() as u32,
            Linktype::ETHERNET,
        );

        assert!(!record.decoded);
        assert_eq!(record.decode_reason, "truncated_tcp");
        assert_eq!(record.src, "");
        assert_eq!(record.protocol, None);
    }

    #[test]
    fn packet_index_rejects_fragmented_or_self_inconsistent_ip_transport() {
        let mut non_initial_ipv4 = ipv4_tcp_packet(false);
        non_initial_ipv4[20..22].copy_from_slice(&1u16.to_be_bytes());

        let mut excluded_ipv4_transport = ipv4_tcp_packet(false);
        excluded_ipv4_transport[16..18].copy_from_slice(&20u16.to_be_bytes());

        let mut oversized_tcp_header = ipv4_tcp_packet(false);
        oversized_tcp_header[46] = 15 << 4;

        let mut invalid_udp_length = vec![0u8; 28];
        invalid_udp_length[0] = 0x45;
        invalid_udp_length[2..4].copy_from_slice(&28u16.to_be_bytes());
        invalid_udp_length[9] = 17;
        invalid_udp_length[12..16].copy_from_slice(&[192, 0, 2, 1]);
        invalid_udp_length[16..20].copy_from_slice(&[198, 51, 100, 2]);
        invalid_udp_length[20..22].copy_from_slice(&53000u16.to_be_bytes());
        invalid_udp_length[22..24].copy_from_slice(&53u16.to_be_bytes());
        invalid_udp_length[24..26].copy_from_slice(&40u16.to_be_bytes());

        let mut fragmented_ipv6 = vec![0u8; 40 + 8 + 20];
        fragmented_ipv6[0] = 0x60;
        fragmented_ipv6[4..6].copy_from_slice(&28u16.to_be_bytes());
        fragmented_ipv6[6] = 44;
        fragmented_ipv6[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        fragmented_ipv6[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]);
        fragmented_ipv6[40] = 6;
        fragmented_ipv6[42..44].copy_from_slice(&8u16.to_be_bytes());
        fragmented_ipv6[48..50].copy_from_slice(&12345u16.to_be_bytes());
        fragmented_ipv6[50..52].copy_from_slice(&443u16.to_be_bytes());
        fragmented_ipv6[60] = 5 << 4;

        let mut malformed_ipv6_fragment = fragmented_ipv6.clone();
        malformed_ipv6_fragment[42..44].copy_from_slice(&2u16.to_be_bytes());

        let mut truncated_ipv6_payload = fragmented_ipv6.clone();
        truncated_ipv6_payload[42..44].copy_from_slice(&0u16.to_be_bytes());
        truncated_ipv6_payload[4..6].copy_from_slice(&128u16.to_be_bytes());

        for (raw, datalink) in [
            (non_initial_ipv4, Linktype::ETHERNET),
            (excluded_ipv4_transport, Linktype::ETHERNET),
            (oversized_tcp_header, Linktype::ETHERNET),
            (invalid_udp_length, Linktype::IPV4),
            (fragmented_ipv6, Linktype::IPV6),
            (malformed_ipv6_fragment, Linktype::IPV6),
            (truncated_ipv6_payload, Linktype::IPV6),
        ] {
            let record = packet_index_record(
                11,
                12.5,
                raw.clone(),
                raw.len() as u32,
                datalink,
            );
            assert!(!record.decoded, "{}", record.decode_reason);
            assert_eq!(record.src_port, None);
            assert_eq!(record.dst_port, None);
            assert_eq!(record.protocol, None);
            assert_eq!(record.tcp_flags, None);
        }
    }
}
