//! Strict aggregate-analysis control frames.
//!
//! This stays deliberately independent from packet decoding so an invalid
//! controller plan is rejected before a PCAP is opened or evidence is read.

const SCHEMA_VERSION: u8 = 1;
const KNOWN_FLAGS: u16 = 0x000f;
const MAX_PLAN_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AnalysisPlan {
    pub(crate) plan_sha256: [u8; 32],
    pub(crate) semantic_plugin_sha256: [u8; 32],
    pub(crate) execution_mode: u8,
    pub(crate) analysis_mode: u8,
    pub(crate) flags: u16,
    pub(crate) target_batch_bytes: u32,
    pub(crate) max_active_conversations: u32,
    pub(crate) max_resume_conversations: u32,
    pub(crate) max_directional_flows: u32,
    pub(crate) max_endpoints: u32,
    pub(crate) max_flow_samples: u16,
    pub(crate) max_flow_sample_bytes: u64,
    pub(crate) max_stream_segments: u32,
    pub(crate) max_stream_bytes: u64,
    pub(crate) source: String,
    pub(crate) session_id: String,
    pub(crate) interface: String,
    pub(crate) sensor_node_id: String,
    pub(crate) selector_programs: Vec<SelectorProgram>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectorProgram {
    pub(crate) program_id: u8,
    pub(crate) candidate_mode: u8,
    pub(crate) clauses: Vec<SelectorClause>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SelectorClause {
    Always,
    LinkClassIn(Vec<u8>),
    EtherTypeIn(Vec<u16>),
    IpProtocolIn(Vec<u8>),
    EitherPortIn(Vec<u16>),
    SourcePortIn(Vec<u16>),
    DestinationPortIn(Vec<u16>),
    TcpFlags { required: u16, forbidden: u16 },
    IcmpTypeIn(Vec<u8>),
    PayloadMinimumLength(u32),
    PayloadPrefixIn(Vec<Vec<u8>>),
    PayloadContainsAny(Vec<Vec<u8>>),
    PayloadByteMask { offset: u16, mask: u8, expected: u8 },
    PayloadDiversity { sample: u16, minimum_distinct: u16 },
    FrameWindowContainsAny { start: u16, end: u16, literals: Vec<Vec<u8>> },
}

pub(crate) struct AnalysisEnd {
    pub(crate) plan_sha256: [u8; 32],
    pub(crate) terminal_status: u8,
    pub(crate) error_code: String,
    pub(crate) counters: [u64; 12],
    pub(crate) first_decoded_timestamp: Option<f64>,
    pub(crate) last_decoded_timestamp: Option<f64>,
    pub(crate) digests: [[u8; 32]; 5],
    pub(crate) timers_ns: [u64; 4],
    pub(crate) high_waters: [u32; 4],
    pub(crate) sample_bytes_high_water: u64,
}

struct Reader<'a> {
    payload: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(payload: &'a [u8]) -> Self { Self { payload, offset: 0 } }

    fn take(&mut self, size: usize, label: &str) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(size).ok_or_else(|| format!("truncated {label}"))?;
        if end > self.payload.len() { return Err(format!("truncated {label}")); }
        let result = &self.payload[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self, label: &str) -> Result<u8, String> {
        Ok(self.take(1, label)?[0])
    }

    fn u16(&mut self, label: &str) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take(2, label)?.try_into().expect("two bytes")))
    }

    fn u32(&mut self, label: &str) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4, label)?.try_into().expect("four bytes")))
    }

    fn u64(&mut self, label: &str) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.take(8, label)?.try_into().expect("eight bytes")))
    }

    fn ascii8(&mut self, maximum: u8, label: &str) -> Result<String, String> {
        let length = self.u8(&format!("{label} length"))?;
        if length > maximum { return Err(format!("{label} exceeds {maximum} bytes")); }
        let value = self.take(length as usize, label)?;
        if !value.is_ascii() { return Err(format!("{label} is not ASCII")); }
        Ok(String::from_utf8(value.to_vec()).expect("validated ASCII"))
    }

    fn finish(&self) -> Result<(), String> {
        if self.offset == self.payload.len() { Ok(()) } else { Err("trailing bytes in analysis payload".into()) }
    }
}

fn in_range(value: u64, minimum: u64, maximum: u64, label: &str) -> Result<(), String> {
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{label} must be {minimum}..{maximum}"));
    }
    Ok(())
}

fn read_literals(reader: &mut Reader<'_>, label: &str) -> Result<Vec<Vec<u8>>, String> {
    let count = reader.u8(&format!("{label} literal count"))?;
    in_range(count as u64, 1, 32, &format!("{label} literal count"))?;
    let mut values = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let length = reader.u16(&format!("{label} literal length"))?;
        in_range(length as u64, 1, 256, &format!("{label} literal length"))?;
        values.push(reader.take(length as usize, label)?.to_vec());
    }
    Ok(values)
}

fn read_u8_values(reader: &mut Reader<'_>, label: &str) -> Result<Vec<u8>, String> {
    let count = reader.u8(&format!("{label} count"))?;
    in_range(count as u64, 1, 255, &format!("{label} count"))?;
    (0..count).map(|_| reader.u8(label)).collect()
}

fn read_u16_values(
    reader: &mut Reader<'_>,
    label: &str,
    maximum_count: u16,
) -> Result<Vec<u16>, String> {
    let count = reader.u16(&format!("{label} count"))?;
    in_range(count as u64, 1, maximum_count as u64, &format!("{label} count"))?;
    (0..count).map(|_| reader.u16(label)).collect()
}

fn decode_selector_clause(reader: &mut Reader<'_>) -> Result<SelectorClause, String> {
    Ok(match reader.u8("selector opcode")? {
        1 => SelectorClause::Always,
        2 => {
            let values = read_u8_values(reader, "link class")?;
            if values.iter().any(|value| !matches!(value, 1 | 2)) {
                return Err("invalid link class selector".into());
            }
            SelectorClause::LinkClassIn(values)
        }
        3 => SelectorClause::EtherTypeIn(read_u16_values(reader, "ethertype", 255)?),
        4 => SelectorClause::IpProtocolIn(read_u8_values(reader, "IP protocol")?),
        5 => SelectorClause::EitherPortIn(read_u16_values(reader, "either port", 512)?),
        6 => SelectorClause::SourcePortIn(read_u16_values(reader, "source port", 512)?),
        7 => SelectorClause::DestinationPortIn(read_u16_values(reader, "destination port", 512)?),
        8 => SelectorClause::TcpFlags {
            required: reader.u16("required TCP flags")?,
            forbidden: reader.u16("forbidden TCP flags")?,
        },
        9 => SelectorClause::IcmpTypeIn(read_u8_values(reader, "ICMP type")?),
        10 => SelectorClause::PayloadMinimumLength(reader.u32("payload minimum length")?),
        11 => SelectorClause::PayloadPrefixIn(read_literals(reader, "payload prefix")?),
        12 => SelectorClause::PayloadContainsAny(read_literals(reader, "payload contains")?),
        13 => SelectorClause::PayloadByteMask {
            offset: reader.u16("payload mask offset")?,
            mask: reader.u8("payload mask")?,
            expected: reader.u8("payload mask expected")?,
        },
        14 => {
            let sample = reader.u16("payload diversity sample")?;
            let minimum_distinct = reader.u16("payload diversity minimum")?;
            if minimum_distinct > sample {
                return Err("payload diversity minimum exceeds sample".into());
            }
            SelectorClause::PayloadDiversity { sample, minimum_distinct }
        }
        15 => {
            let start = reader.u16("frame window start")?;
            let end = reader.u16("frame window end")?;
            if end < start {
                return Err("frame window end precedes start".into());
            }
            SelectorClause::FrameWindowContainsAny {
                start,
                end,
                literals: read_literals(reader, "frame window")?,
            }
        }
        value => return Err(format!("unknown selector opcode {value}")),
    })
}

/// Decodes and validates the schema-1 plan before a child starts analysis.
pub(crate) fn decode_analysis_plan(payload: &[u8]) -> Result<AnalysisPlan, String> {
    if payload.len() > MAX_PLAN_BYTES { return Err("analysis plan exceeds 1048576 bytes".into()); }
    let mut reader = Reader::new(payload);
    let schema = reader.u8("analysis plan schema")?;
    if schema != SCHEMA_VERSION { return Err(format!("unsupported analysis plan schema {schema}")); }
    let plan_sha256: [u8; 32] = reader.take(32, "plan digest")?.try_into().expect("32 bytes");
    let semantic_plugin_sha256: [u8; 32] = reader.take(32, "semantic plugin digest")?.try_into().expect("32 bytes");
    let execution_mode = reader.u8("execution mode")?;
    if !matches!(execution_mode, 1 | 2) { return Err("unsupported execution mode".into()); }
    let analysis_mode = reader.u8("analysis mode")?;
    if !matches!(analysis_mode, 1 | 2) { return Err("unsupported analysis mode".into()); }
    let flags = reader.u16("flags")?;
    if flags & !KNOWN_FLAGS != 0 { return Err("unknown analysis plan flags".into()); }
    let target_batch_bytes = reader.u32("target batch bytes")?;
    in_range(target_batch_bytes as u64, 1, 8 * 1024 * 1024, "target batch bytes")?;
    let max_active_conversations = reader.u32("max active conversations")?;
    in_range(max_active_conversations as u64, 1, 100_000, "max active conversations")?;
    let max_resume_conversations = reader.u32("max resume conversations")?;
    in_range(max_resume_conversations as u64, 1, 100_000, "max resume conversations")?;
    let max_directional_flows = reader.u32("max directional flows")?;
    in_range(max_directional_flows as u64, 1, 220_000, "max directional flows")?;
    let max_endpoints = reader.u32("max endpoints")?;
    in_range(max_endpoints as u64, 1, 440_000, "max endpoints")?;
    let max_flow_samples = reader.u16("max flow samples")?;
    in_range(max_flow_samples as u64, 1, 500, "max flow samples")?;
    let max_flow_sample_bytes = reader.u64("max flow sample bytes")?;
    in_range(max_flow_sample_bytes, 1, 268_435_456, "max flow sample bytes")?;
    let max_stream_segments = reader.u32("max stream segments")?;
    in_range(max_stream_segments as u64, 1, 10_000, "max stream segments")?;
    let max_stream_bytes = reader.u64("max stream bytes")?;
    in_range(max_stream_bytes, 1, 16_777_216, "max stream bytes")?;
    let source = reader.ascii8(255, "source")?;
    let session_id = reader.ascii8(255, "session ID")?;
    let interface = reader.ascii8(64, "interface")?;
    let sensor_node_id = reader.ascii8(128, "sensor node ID")?;
    let selector_count = reader.u8("selector program count")?;
    in_range(selector_count as u64, 0, 64, "selector program count")?;
    let mut selector_programs = Vec::with_capacity(selector_count as usize);
    let mut seen_program_ids = std::collections::HashSet::new();
    for _ in 0..selector_count {
        let program_id = reader.u8("selector program ID")?;
        if program_id > 63 || !seen_program_ids.insert(program_id) {
            return Err("selector program IDs must be unique bytes from 0 to 63".into());
        }
        let candidate_mode = reader.u8("selector candidate mode")?;
        if !matches!(candidate_mode, 1 | 2) {
            return Err("invalid selector candidate mode".into());
        }
        let clause_count = reader.u8("selector clause count")?;
        in_range(clause_count as u64, 1, 16, "selector clause count")?;
        let mut clauses = Vec::with_capacity(clause_count as usize);
        for _ in 0..clause_count {
            clauses.push(decode_selector_clause(&mut reader)?);
        }
        selector_programs.push(SelectorProgram { program_id, candidate_mode, clauses });
    }
    reader.finish()?;

    // Structural errors intentionally win over a digest mismatch so the
    // coordinator receives an actionable compatibility failure.
    if super::sha256(&payload[33..]) != plan_sha256 { return Err("analysis plan digest mismatch".into()); }
    Ok(AnalysisPlan {
        plan_sha256, semantic_plugin_sha256, execution_mode, analysis_mode, flags,
        target_batch_bytes, max_active_conversations, max_resume_conversations,
        max_directional_flows, max_endpoints, max_flow_samples, max_flow_sample_bytes,
        max_stream_segments, max_stream_bytes, source, session_id, interface,
        sensor_node_id, selector_programs,
    })
}

fn push_ascii8(payload: &mut Vec<u8>, value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if !value.is_ascii() { return Err(format!("{label} is not ASCII")); }
    if value.len() > maximum { return Err(format!("{label} exceeds {maximum} bytes")); }
    payload.push(value.len() as u8);
    payload.extend_from_slice(value.as_bytes());
    Ok(())
}

/// Encodes the first aggregate response.  Python must validate this before
/// accepting any evidence-bearing frame.
pub(crate) fn encode_analysis_hello(
    plan: &AnalysisPlan,
    sensor_version: &str,
    pcap_datalink: i32,
    normalized_link_type: &str,
    capability_bits: u64,
) -> Result<Vec<u8>, String> {
    let mut payload = vec![SCHEMA_VERSION];
    payload.extend_from_slice(&plan.plan_sha256);
    push_ascii8(&mut payload, sensor_version, 32, "sensor version")?;
    payload.extend_from_slice(&pcap_datalink.to_be_bytes());
    push_ascii8(&mut payload, normalized_link_type, 32, "normalized link type")?;
    payload.extend_from_slice(&capability_bits.to_be_bytes());
    Ok(payload)
}

pub(crate) fn encode_analysis_end(end: &AnalysisEnd) -> Result<Vec<u8>, String> {
    if !matches!(end.terminal_status, 1 | 2 | 3) {
        return Err("unsupported analysis terminal status".into());
    }
    if end.first_decoded_timestamp.is_some_and(|value| !value.is_finite())
        || end.last_decoded_timestamp.is_some_and(|value| !value.is_finite())
    {
        return Err("analysis terminal timestamp must be finite".into());
    }
    let mut payload = vec![SCHEMA_VERSION];
    payload.extend_from_slice(&end.plan_sha256);
    payload.push(end.terminal_status);
    push_ascii8(&mut payload, &end.error_code, 128, "analysis error code")?;
    for value in end.counters {
        payload.extend_from_slice(&value.to_be_bytes());
    }
    for value in [end.first_decoded_timestamp, end.last_decoded_timestamp] {
        payload.push(u8::from(value.is_some()));
        payload.extend_from_slice(&value.unwrap_or_default().to_be_bytes());
    }
    for digest in end.digests {
        payload.extend_from_slice(&digest);
    }
    for value in end.timers_ns {
        payload.extend_from_slice(&value.to_be_bytes());
    }
    for value in end.high_waters {
        payload.extend_from_slice(&value.to_be_bytes());
    }
    payload.extend_from_slice(&end.sample_bytes_high_water.to_be_bytes());
    Ok(payload)
}

#[cfg(test)]
pub(crate) fn test_plan_payload() -> Vec<u8> {
    let mut payload = vec![SCHEMA_VERSION];
    payload.extend_from_slice(&[0; 32]);
    payload.extend_from_slice(&[0x11; 32]);
    payload.extend_from_slice(&[1, 1]);
    payload.extend_from_slice(&0x0009u16.to_be_bytes());
    payload.extend_from_slice(&(1024 * 1024u32).to_be_bytes());
    for value in [100_000u32, 100_000, 220_000, 440_000] { payload.extend_from_slice(&value.to_be_bytes()); }
    payload.extend_from_slice(&500u16.to_be_bytes());
    payload.extend_from_slice(&268_435_456u64.to_be_bytes());
    payload.extend_from_slice(&10_000u32.to_be_bytes());
    payload.extend_from_slice(&16_777_216u64.to_be_bytes());
    for value in ["pcap:fixture", "rust-replay", "pcap", "local"] {
        payload.push(value.len() as u8);
        payload.extend_from_slice(value.as_bytes());
    }
    payload.push(0);
    let digest = super::sha256(&payload[33..]);
    payload[1..33].copy_from_slice(&digest);
    payload
}
