//! Schema-1 aggregate analysis data frames.

use crate::analysis::{
    AnalysisEvent, AnalysisObservation, ConversationDirection, ConversationState,
    DirectionalFlowState,
};

const SCHEMA_VERSION: u8 = 1;

fn ascii8(output: &mut Vec<u8>, value: &str, maximum: usize) -> Result<(), String> {
    if !value.is_ascii() || value.len() > maximum {
        return Err(format!("analysis text exceeds {maximum} ASCII bytes"));
    }
    output.push(value.len() as u8);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

pub(crate) fn encode_work_item(
    batch_sequence: u32,
    packet_ordinal: u64,
    event: &AnalysisEvent,
    observation: &AnalysisObservation,
    raw_frame: &[u8],
    candidate_mode: u8,
    matched_programs: u64,
) -> Result<Vec<u8>, String> {
    if !matches!(candidate_mode, 0 | 1 | 2) {
        return Err("invalid candidate mode".into());
    }
    if (candidate_mode == 0) != raw_frame.is_empty() {
        return Err("raw frame presence disagrees with candidate mode".into());
    }
    let endpoint_count = u16::try_from(observation.endpoint_definitions.len())
        .map_err(|_| "too many endpoint definitions")?;
    let mut output = vec![SCHEMA_VERSION];
    output.extend_from_slice(&batch_sequence.to_be_bytes());
    output.extend_from_slice(&endpoint_count.to_be_bytes());
    output.extend_from_slice(&u16::from(observation.flow_definition.is_some()).to_be_bytes());
    output.extend_from_slice(&u16::from(observation.conversation_definition.is_some()).to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());

    for definition in &observation.endpoint_definitions {
        output.extend_from_slice(&definition.endpoint_id.to_be_bytes());
        ascii8(&mut output, &definition.address, 45)?;
    }
    if let Some(definition) = &observation.flow_definition {
        output.extend_from_slice(&definition.flow_id.to_be_bytes());
        output.extend_from_slice(&definition.source_endpoint_id.to_be_bytes());
        output.extend_from_slice(&definition.destination_endpoint_id.to_be_bytes());
        output.extend_from_slice(&definition.source_port.to_be_bytes());
        output.extend_from_slice(&definition.destination_port.to_be_bytes());
        output.push(definition.protocol);
    }
    if let Some(definition) = &observation.conversation_definition {
        output.extend_from_slice(&definition.conversation_id.to_be_bytes());
        output.extend_from_slice(&definition.endpoint_a_id.to_be_bytes());
        output.extend_from_slice(&definition.endpoint_a_port.to_be_bytes());
        output.extend_from_slice(&definition.endpoint_b_id.to_be_bytes());
        output.extend_from_slice(&definition.endpoint_b_port.to_be_bytes());
        output.extend_from_slice(&definition.initiator_id.to_be_bytes());
        output.extend_from_slice(&definition.initiator_port.to_be_bytes());
        output.extend_from_slice(&definition.responder_id.to_be_bytes());
        output.extend_from_slice(&definition.responder_port.to_be_bytes());
        output.push(definition.protocol);
        output.extend_from_slice(&definition.first_seen.to_be_bytes());
    }

    output.extend_from_slice(&packet_ordinal.to_be_bytes());
    output.extend_from_slice(&event.timestamp.to_be_bytes());
    output.extend_from_slice(&event.size.to_be_bytes());
    output.extend_from_slice(&observation.flow_id.to_be_bytes());
    output.extend_from_slice(&observation.conversation_id.to_be_bytes());
    output.push(0); // hop limit unavailable in the current decoder
    output.extend_from_slice(&event.tcp_flags.to_be_bytes());
    output.push(match observation.direction {
        ConversationDirection::ToResponder => 1,
        ConversationDirection::ToInitiator => 2,
    });
    output.push(candidate_mode);
    output.extend_from_slice(&matched_programs.to_be_bytes());
    output.extend_from_slice(&observation.flow.start_time.to_be_bytes());
    output.extend_from_slice(&observation.flow.packet_count.to_be_bytes());
    output.extend_from_slice(&observation.flow.byte_count.to_be_bytes());
    output.extend_from_slice(&observation.flow.syn_count.to_be_bytes());
    output.extend_from_slice(&observation.flow.syn_ack_count.to_be_bytes());
    output.extend_from_slice(&observation.flow.rst_count.to_be_bytes());
    output.extend_from_slice(&observation.conversation.generation.to_be_bytes());
    output.extend_from_slice(&observation.conversation.to_responder_packets.to_be_bytes());
    output.extend_from_slice(&observation.conversation.to_responder_bytes.to_be_bytes());
    output.extend_from_slice(&observation.conversation.to_initiator_packets.to_be_bytes());
    output.extend_from_slice(&observation.conversation.to_initiator_bytes.to_be_bytes());
    output.extend_from_slice(&observation.conversation.syn_count.to_be_bytes());
    output.extend_from_slice(&observation.conversation.syn_ack_count.to_be_bytes());
    output.extend_from_slice(&observation.conversation.rst_count.to_be_bytes());
    output.extend_from_slice(&observation.syn_delta.to_be_bytes());
    output.extend_from_slice(&observation.syn_ack_delta.to_be_bytes());
    output.extend_from_slice(&observation.rst_delta.to_be_bytes());
    output.push(u8::from(observation.conversation.established));
    output.extend_from_slice(&(raw_frame.len() as u32).to_be_bytes());
    output.extend_from_slice(raw_frame);
    Ok(output)
}

pub(crate) fn encode_flow_batch(
    batch_sequence: u32,
    records: &[(u32, DirectionalFlowState)],
) -> Result<Vec<u8>, String> {
    let count = u16::try_from(records.len()).map_err(|_| "too many flow records in one batch")?;
    let mut output = vec![SCHEMA_VERSION];
    output.extend_from_slice(&batch_sequence.to_be_bytes());
    output.extend_from_slice(&count.to_be_bytes());
    for (flow_id, state) in records {
        output.extend_from_slice(&flow_id.to_be_bytes());
        output.extend_from_slice(&1u32.to_be_bytes());
        output.push(2); // terminal
        output.extend_from_slice(&state.start_time.to_be_bytes());
        output.extend_from_slice(&state.last_seen.to_be_bytes());
        output.extend_from_slice(&state.packet_count.to_be_bytes());
        output.extend_from_slice(&state.byte_count.to_be_bytes());
        output.extend_from_slice(&state.syn_count.to_be_bytes());
        output.extend_from_slice(&state.syn_ack_count.to_be_bytes());
        output.extend_from_slice(&state.rst_count.to_be_bytes());
        let sample_count = u16::try_from(state.samples.len()).map_err(|_| "too many flow samples")?;
        output.extend_from_slice(&sample_count.to_be_bytes());
        for sample in &state.samples {
            output.extend_from_slice(&sample.size.to_be_bytes());
            output.extend_from_slice(&sample.timestamp.to_be_bytes());
        }
    }
    Ok(output)
}

pub(crate) fn encode_conversation_batch(
    batch_sequence: u32,
    records: &[(u32, ConversationState)],
) -> Result<Vec<u8>, String> {
    let count = u16::try_from(records.len()).map_err(|_| "too many conversation records in one batch")?;
    let mut output = vec![SCHEMA_VERSION];
    output.extend_from_slice(&batch_sequence.to_be_bytes());
    output.extend_from_slice(&count.to_be_bytes());
    for (conversation_id, state) in records {
        output.extend_from_slice(&conversation_id.to_be_bytes());
        output.push(2); // terminal
        output.extend_from_slice(&state.last_seen.to_be_bytes());
        output.extend_from_slice(&state.generation.to_be_bytes());
        output.extend_from_slice(&state.to_responder_packets.to_be_bytes());
        output.extend_from_slice(&state.to_responder_bytes.to_be_bytes());
        output.extend_from_slice(&state.to_initiator_packets.to_be_bytes());
        output.extend_from_slice(&state.to_initiator_bytes.to_be_bytes());
        output.extend_from_slice(&state.syn_count.to_be_bytes());
        output.extend_from_slice(&state.syn_ack_count.to_be_bytes());
        output.extend_from_slice(&state.rst_count.to_be_bytes());
        output.push(u8::from(state.established));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{AnalysisEvent, AnalysisState};

    #[test]
    fn work_encoder_emits_definitions_once_and_rejects_raw_mode_disagreement() {
        let event = AnalysisEvent {
            timestamp: 1.0, src: "10.0.0.1".into(), dst: "10.0.0.2".into(),
            src_port: 50000, dst_port: 443, protocol: 6, size: 60, tcp_flags: 0x02,
        };
        let mut state = AnalysisState::new(10, 10);
        let first = state.observe(event.clone()).unwrap();
        let encoded = encode_work_item(1, 1, &event, &first, b"frame", 2, 0).unwrap();
        assert_eq!(encoded[0], 1);
        assert_eq!(u16::from_be_bytes(encoded[5..7].try_into().unwrap()), 2);
        assert!(encode_work_item(2, 2, &event, &first, b"frame", 0, 0).is_err());

        let second = state.observe(event.clone()).unwrap();
        let encoded = encode_work_item(2, 2, &event, &second, b"frame", 2, 0).unwrap();
        assert_eq!(u16::from_be_bytes(encoded[5..7].try_into().unwrap()), 0);
    }
}
