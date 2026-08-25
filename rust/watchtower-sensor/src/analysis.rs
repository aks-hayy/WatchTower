use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub(crate) struct AnalysisEvent {
    pub(crate) timestamp: f64,
    pub(crate) src: String,
    pub(crate) dst: String,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) protocol: u8,
    pub(crate) size: u32,
    pub(crate) tcp_flags: u16,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Endpoint {
    pub(crate) address: String,
    pub(crate) port: u16,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct FlowKey {
    pub(crate) src: Endpoint,
    pub(crate) dst: Endpoint,
    pub(crate) protocol: u8,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ConversationKey {
    pub(crate) first: Endpoint,
    pub(crate) second: Endpoint,
    pub(crate) protocol: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FlowSample {
    pub(crate) size: u32,
    pub(crate) timestamp: f64,
}

#[derive(Clone, Debug)]
pub(crate) struct DirectionalFlowState {
    pub(crate) key: FlowKey,
    pub(crate) start_time: f64,
    pub(crate) last_seen: f64,
    pub(crate) packet_count: u64,
    pub(crate) byte_count: u64,
    pub(crate) syn_count: u64,
    pub(crate) syn_ack_count: u64,
    pub(crate) rst_count: u64,
    pub(crate) samples: Vec<FlowSample>,
}

#[derive(Clone, Debug)]
pub(crate) struct ConversationState {
    pub(crate) key: ConversationKey,
    pub(crate) initiator: Endpoint,
    pub(crate) responder: Endpoint,
    pub(crate) first_seen: f64,
    pub(crate) last_seen: f64,
    pub(crate) to_responder_packets: u64,
    pub(crate) to_responder_bytes: u64,
    pub(crate) to_initiator_packets: u64,
    pub(crate) to_initiator_bytes: u64,
    pub(crate) syn_count: u64,
    pub(crate) syn_ack_count: u64,
    pub(crate) rst_count: u64,
    pub(crate) established: bool,
    pub(crate) generation: u64,
    saw_initial_syn: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConversationDirection {
    ToResponder,
    ToInitiator,
}

#[derive(Clone, Debug)]
pub(crate) struct AnalysisObservation {
    pub(crate) flow: DirectionalFlowState,
    pub(crate) conversation: ConversationState,
    pub(crate) flow_id: u32,
    pub(crate) conversation_id: u32,
    pub(crate) endpoint_definitions: Vec<EndpointDefinition>,
    pub(crate) flow_definition: Option<FlowDefinition>,
    pub(crate) conversation_definition: Option<ConversationDefinition>,
    pub(crate) direction: ConversationDirection,
    pub(crate) syn_delta: u32,
    pub(crate) syn_ack_delta: u32,
    pub(crate) rst_delta: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct EndpointDefinition {
    pub(crate) endpoint_id: u32,
    pub(crate) address: String,
}

#[derive(Clone, Debug)]
pub(crate) struct FlowDefinition {
    pub(crate) flow_id: u32,
    pub(crate) source_endpoint_id: u32,
    pub(crate) destination_endpoint_id: u32,
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    pub(crate) protocol: u8,
}

#[derive(Clone, Debug)]
pub(crate) struct ConversationDefinition {
    pub(crate) conversation_id: u32,
    pub(crate) endpoint_a_id: u32,
    pub(crate) endpoint_a_port: u16,
    pub(crate) endpoint_b_id: u32,
    pub(crate) endpoint_b_port: u16,
    pub(crate) initiator_id: u32,
    pub(crate) initiator_port: u16,
    pub(crate) responder_id: u32,
    pub(crate) responder_port: u16,
    pub(crate) protocol: u8,
    pub(crate) first_seen: f64,
}

pub(crate) struct AnalysisState {
    max_samples: usize,
    max_sample_bytes: u64,
    sample_bytes: u64,
    max_directional_flows: usize,
    max_endpoints: usize,
    max_conversations: usize,
    max_resume_conversations: usize,
    flows: HashMap<FlowKey, DirectionalFlowState>,
    conversations: HashMap<ConversationKey, ConversationState>,
    resume_conversations: HashMap<ConversationKey, ConversationState>,
    endpoint_ids: HashMap<String, u32>,
    flow_ids: HashMap<FlowKey, u32>,
    conversation_ids: HashMap<ConversationKey, ConversationDefinition>,
    next_endpoint_id: u32,
    next_flow_id: u32,
    next_conversation_id: u32,
}

impl AnalysisState {
    pub(crate) fn new(max_samples: usize, max_conversations: usize) -> Self {
        Self::with_protocol_limits(
            max_samples, usize::MAX, max_conversations, max_conversations, usize::MAX,
        )
    }

    pub(crate) fn with_limits(
        max_samples: usize,
        max_conversations: usize,
        max_resume_conversations: usize,
    ) -> Self {
        Self::with_protocol_limits(
            max_samples, usize::MAX, max_conversations, max_resume_conversations, usize::MAX,
        )
    }

    pub(crate) fn with_resource_limits(
        max_samples: usize,
        max_directional_flows: usize,
        max_conversations: usize,
        max_resume_conversations: usize,
    ) -> Self {
        Self::with_protocol_limits(
            max_samples,
            max_directional_flows,
            max_conversations,
            max_resume_conversations,
            usize::MAX,
        )
    }

    pub(crate) fn with_protocol_limits(
        max_samples: usize,
        max_directional_flows: usize,
        max_conversations: usize,
        max_resume_conversations: usize,
        max_endpoints: usize,
    ) -> Self {
        Self::with_sample_byte_limit(
            max_samples,
            max_directional_flows,
            max_conversations,
            max_resume_conversations,
            max_endpoints,
            u64::MAX,
        )
    }

    pub(crate) fn with_sample_byte_limit(
        max_samples: usize,
        max_directional_flows: usize,
        max_conversations: usize,
        max_resume_conversations: usize,
        max_endpoints: usize,
        max_sample_bytes: u64,
    ) -> Self {
        Self {
            max_samples,
            max_sample_bytes,
            sample_bytes: 0,
            max_directional_flows,
            max_endpoints,
            max_conversations,
            max_resume_conversations,
            flows: HashMap::new(),
            conversations: HashMap::new(),
            resume_conversations: HashMap::new(),
            endpoint_ids: HashMap::new(),
            flow_ids: HashMap::new(),
            conversation_ids: HashMap::new(),
            next_endpoint_id: 1,
            next_flow_id: 1,
            next_conversation_id: 1,
        }
    }

    pub(crate) fn observe(&mut self, event: AnalysisEvent) -> Result<AnalysisObservation, String> {
        if !event.timestamp.is_finite() {
            return Err("packet timestamp must be finite".into());
        }
        let source = Endpoint { address: event.src, port: event.src_port };
        let destination = Endpoint { address: event.dst, port: event.dst_port };
        let flow_key = FlowKey { src: source.clone(), dst: destination.clone(), protocol: event.protocol };
        if !self.flows.contains_key(&flow_key) && self.flows.len() >= self.max_directional_flows {
            return Err("directional flow capacity exceeded".into());
        }
        let new_endpoint_count = [&source.address, &destination.address].into_iter()
            .filter(|address| !self.endpoint_ids.contains_key(*address))
            .collect::<std::collections::HashSet<_>>()
            .len();
        if self.endpoint_ids.len().saturating_add(new_endpoint_count) > self.max_endpoints {
            return Err("endpoint capacity exceeded".into());
        }
        let mut endpoint_definitions = Vec::new();
        let source_endpoint_id = self.intern_endpoint(&source.address, &mut endpoint_definitions)?;
        let destination_endpoint_id = self.intern_endpoint(&destination.address, &mut endpoint_definitions)?;
        let (flow_id, flow_definition) = if let Some(value) = self.flow_ids.get(&flow_key) {
            (*value, None)
        } else {
            let value = self.next_flow_id;
            self.next_flow_id = self.next_flow_id.checked_add(1).ok_or("flow ID overflow")?;
            self.flow_ids.insert(flow_key.clone(), value);
            (value, Some(FlowDefinition {
                flow_id: value,
                source_endpoint_id,
                destination_endpoint_id,
                source_port: source.port,
                destination_port: destination.port,
                protocol: event.protocol,
            }))
        };
        let syn_delta = u32::from(
            event.protocol == 6 && event.tcp_flags & 0x02 != 0 && event.tcp_flags & 0x10 == 0,
        );
        let syn_ack_delta = u32::from(event.protocol == 6 && event.tcp_flags & 0x12 == 0x12);
        let rst_delta = u32::from(event.protocol == 6 && event.tcp_flags & 0x04 != 0);
        let flow = self.flows.entry(flow_key.clone()).or_insert_with(|| DirectionalFlowState {
            key: flow_key,
            start_time: event.timestamp,
            last_seen: event.timestamp,
            packet_count: 0,
            byte_count: 0,
            syn_count: 0,
            syn_ack_count: 0,
            rst_count: 0,
            samples: Vec::with_capacity(self.max_samples.min(500)),
        });
        flow.last_seen = event.timestamp;
        flow.packet_count += 1;
        flow.byte_count += u64::from(event.size);
        if event.protocol == 6 {
            flow.syn_count += u64::from(syn_delta);
            flow.syn_ack_count += u64::from(syn_ack_delta);
            flow.rst_count += u64::from(rst_delta);
        }
        if flow.samples.len() < self.max_samples
            && self.sample_bytes.saturating_add(12) <= self.max_sample_bytes
        {
            flow.samples.push(FlowSample { size: event.size, timestamp: event.timestamp });
            self.sample_bytes = self.sample_bytes.saturating_add(12);
        }
        let flow_snapshot = flow.clone();

        let (first, second) = canonical_endpoints(source.clone(), destination.clone());
        let conversation_key = ConversationKey { first, second, protocol: event.protocol };
        let (conversation_id, conversation_definition) = if let Some(value) = self.conversation_ids.get(&conversation_key) {
            (value.conversation_id, None)
        } else {
            let value = self.next_conversation_id;
            self.next_conversation_id = self.next_conversation_id.checked_add(1).ok_or("conversation ID overflow")?;
            let first_id = *self.endpoint_ids.get(&conversation_key.first.address).expect("interned endpoint");
            let second_id = *self.endpoint_ids.get(&conversation_key.second.address).expect("interned endpoint");
            let definition = ConversationDefinition {
                conversation_id: value,
                endpoint_a_id: first_id,
                endpoint_a_port: conversation_key.first.port,
                endpoint_b_id: second_id,
                endpoint_b_port: conversation_key.second.port,
                initiator_id: source_endpoint_id,
                initiator_port: source.port,
                responder_id: destination_endpoint_id,
                responder_port: destination.port,
                protocol: event.protocol,
                first_seen: event.timestamp,
            };
            self.conversation_ids.insert(conversation_key.clone(), definition.clone());
            (value, Some(definition))
        };
        let initial_syn = event.protocol == 6
            && event.tcp_flags & 0x02 != 0
            && event.tcp_flags & 0x10 == 0;
        if !self.conversations.contains_key(&conversation_key) {
            if self.max_conversations == 0 {
                return Err("active conversation capacity must be nonzero".into());
            }
            let resumed = self.resume_conversations.remove(&conversation_key);
            if self.conversations.len() >= self.max_conversations {
                self.evict_oldest_conversation();
            }
            if let Some(value) = resumed {
                self.conversations.insert(conversation_key.clone(), value);
            }
        }
        let conversation = self.conversations.entry(conversation_key.clone()).or_insert_with(|| ConversationState {
            key: conversation_key,
            initiator: source.clone(),
            responder: destination.clone(),
            first_seen: event.timestamp,
            last_seen: event.timestamp,
            to_responder_packets: 0,
            to_responder_bytes: 0,
            to_initiator_packets: 0,
            to_initiator_bytes: 0,
            syn_count: 0,
            syn_ack_count: 0,
            rst_count: 0,
            established: false,
            generation: 0,
            saw_initial_syn: initial_syn,
        });
        conversation.last_seen = event.timestamp;
        conversation.generation += 1;
        conversation.syn_count += u64::from(syn_delta);
        conversation.syn_ack_count += u64::from(syn_ack_delta);
        conversation.rst_count += u64::from(rst_delta);
        let direction = if source == conversation.initiator {
            conversation.to_responder_packets += 1;
            conversation.to_responder_bytes += u64::from(event.size);
            ConversationDirection::ToResponder
        } else {
            conversation.to_initiator_packets += 1;
            conversation.to_initiator_bytes += u64::from(event.size);
            if conversation.saw_initial_syn
                && event.protocol == 6
                && event.tcp_flags & 0x12 == 0x12
            {
                conversation.established = true;
            }
            ConversationDirection::ToInitiator
        };
        Ok(AnalysisObservation {
            flow: flow_snapshot,
            conversation: conversation.clone(),
            flow_id,
            conversation_id,
            endpoint_definitions,
            flow_definition,
            conversation_definition,
            direction,
            syn_delta,
            syn_ack_delta,
            rst_delta,
        })
    }

    fn intern_endpoint(
        &mut self,
        address: &str,
        definitions: &mut Vec<EndpointDefinition>,
    ) -> Result<u32, String> {
        if let Some(value) = self.endpoint_ids.get(address) {
            return Ok(*value);
        }
        let value = self.next_endpoint_id;
        self.next_endpoint_id = self.next_endpoint_id.checked_add(1).ok_or("endpoint ID overflow")?;
        self.endpoint_ids.insert(address.to_string(), value);
        definitions.push(EndpointDefinition { endpoint_id: value, address: address.to_string() });
        Ok(value)
    }

    pub(crate) fn directional_flows(&self) -> Vec<DirectionalFlowState> {
        let mut values: Vec<_> = self.flows.values().cloned().collect();
        values.sort_by(|left, right| left.key.cmp(&right.key));
        values
    }

    pub(crate) fn conversations(&self) -> Vec<ConversationState> {
        let mut values: Vec<_> = self.conversations.values().cloned().collect();
        values.sort_by(|left, right| left.key.cmp(&right.key));
        values
    }

    pub(crate) fn directional_flow_records(&self) -> Vec<(u32, DirectionalFlowState)> {
        let mut values: Vec<_> = self.flows.iter().map(|(key, state)| {
            (*self.flow_ids.get(key).expect("every flow has an immutable ID"), state.clone())
        }).collect();
        values.sort_by_key(|item| item.0);
        values
    }

    pub(crate) fn conversation_records(&self) -> Vec<(u32, ConversationState)> {
        let mut values: Vec<_> = self.conversations.iter()
            .chain(self.resume_conversations.iter())
            .map(|(key, state)| {
                (self.conversation_ids.get(key).expect("every conversation has an immutable ID").conversation_id, state.clone())
            })
            .collect();
        values.sort_by_key(|item| item.0);
        values
    }

    pub(crate) fn active_conversation_count(&self) -> usize {
        self.conversations.len()
    }

    pub(crate) fn resume_conversation_count(&self) -> usize {
        self.resume_conversations.len()
    }

    pub(crate) fn endpoint_count(&self) -> usize {
        self.endpoint_ids.len()
    }

    pub(crate) fn directional_flow_count(&self) -> usize {
        self.flows.len()
    }

    pub(crate) fn sample_bytes(&self) -> u64 {
        self.sample_bytes
    }

    fn evict_oldest_conversation(&mut self) {
        let oldest = self.conversations.iter().min_by(|(left_key, left), (right_key, right)| {
            left.last_seen.total_cmp(&right.last_seen).then_with(|| left_key.cmp(right_key))
        }).map(|(key, _)| key.clone());
        let Some(key) = oldest else { return; };
        let Some(value) = self.conversations.remove(&key) else { return; };
        if self.max_resume_conversations == 0 {
            return;
        }
        if self.resume_conversations.len() >= self.max_resume_conversations {
            let resume_oldest = self.resume_conversations.iter().min_by(|(left_key, left), (right_key, right)| {
                left.last_seen.total_cmp(&right.last_seen).then_with(|| left_key.cmp(right_key))
            }).map(|(key, _)| key.clone());
            if let Some(resume_key) = resume_oldest {
                self.resume_conversations.remove(&resume_key);
            }
        }
        self.resume_conversations.insert(key, value);
    }
}

fn canonical_endpoints(first: Endpoint, second: Endpoint) -> (Endpoint, Endpoint) {
    if endpoint_order(&first) <= endpoint_order(&second) { (first, second) } else { (second, first) }
}

fn endpoint_order(endpoint: &Endpoint) -> (u8, [u8; 16], u16) {
    let mut bytes = [0u8; 16];
    match IpAddr::from_str(&endpoint.address) {
        Ok(IpAddr::V4(address)) => {
            bytes[..4].copy_from_slice(&address.octets());
            (4, bytes, endpoint.port)
        }
        Ok(IpAddr::V6(address)) => (6, address.octets(), endpoint.port),
        Err(_) => (0, bytes, endpoint.port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(src: &str, dst: &str, sport: u16, dport: u16, flags: u16, timestamp: f64) -> AnalysisEvent {
        AnalysisEvent {
            timestamp,
            src: src.into(),
            dst: dst.into(),
            src_port: sport,
            dst_port: dport,
            protocol: 6,
            size: 60,
            tcp_flags: flags,
        }
    }

    #[test]
    fn reverse_tcp_directions_share_one_conversation_and_preserve_roles() {
        let mut state = AnalysisState::new(500, 100);
        state.observe(tcp("10.0.0.10", "10.0.0.2", 51000, 443, 0x02, 1.0)).unwrap();
        state.observe(tcp("10.0.0.2", "10.0.0.10", 443, 51000, 0x12, 2.0)).unwrap();
        state.observe(tcp("10.0.0.10", "10.0.0.2", 51000, 443, 0x10, 3.0)).unwrap();

        assert_eq!(state.directional_flows().len(), 2);
        let conversations = state.conversations();
        assert_eq!(conversations.len(), 1);
        let conversation = &conversations[0];
        assert_eq!(conversation.initiator.address, "10.0.0.10");
        assert_eq!(conversation.responder.address, "10.0.0.2");
        assert_eq!(conversation.to_responder_packets, 2);
        assert_eq!(conversation.to_initiator_packets, 1);
        assert_eq!(conversation.to_responder_bytes, 120);
        assert_eq!(conversation.to_initiator_bytes, 60);
        assert_eq!(conversation.first_seen, 1.0);
        assert!(conversation.established);
        assert_eq!(conversation.generation, 3);
    }

    #[test]
    fn directional_samples_are_bounded_without_changing_scalar_counts() {
        let mut state = AnalysisState::new(2, 100);
        for index in 0..4 {
            state.observe(tcp("10.0.0.1", "10.0.0.20", 50000, 80, 0x10, index as f64)).unwrap();
        }

        let flows = state.directional_flows();
        assert_eq!(flows[0].packet_count, 4);
        assert_eq!(flows[0].byte_count, 240);
        assert_eq!(flows[0].samples.len(), 2);
        assert_eq!(flows[0].samples[0].timestamp, 0.0);
        assert_eq!(flows[0].samples[1].timestamp, 1.0);
    }

    #[test]
    fn evicted_conversation_resumes_roles_and_generation_with_bounded_state() {
        let mut state = AnalysisState::with_limits(500, 1, 2);
        state.observe(tcp("10.0.0.1", "10.0.0.2", 50000, 443, 0x02, 1.0)).unwrap();
        state.observe(tcp("10.0.0.3", "10.0.0.4", 50001, 80, 0x02, 2.0)).unwrap();
        assert_eq!(state.active_conversation_count(), 1);
        assert_eq!(state.resume_conversation_count(), 1);

        state.observe(tcp("10.0.0.2", "10.0.0.1", 443, 50000, 0x12, 3.0)).unwrap();
        let conversation = state.conversations().into_iter()
            .find(|item| item.initiator.address == "10.0.0.1")
            .expect("resumed conversation");

        assert_eq!(conversation.generation, 2);
        assert_eq!(conversation.first_seen, 1.0);
        assert_eq!(conversation.initiator.address, "10.0.0.1");
        assert!(conversation.established);
        assert_eq!(state.active_conversation_count(), 1);
        assert_eq!(state.resume_conversation_count(), 1);
        assert_eq!(state.conversation_records().len(), 2);
    }

    #[test]
    fn observations_expose_direction_and_tcp_outcome_deltas() {
        let mut state = AnalysisState::new(500, 100);
        let syn = state.observe(tcp("10.0.0.10", "10.0.0.20", 51000, 443, 0x02, 1.0)).unwrap();
        assert_eq!(syn.direction, ConversationDirection::ToResponder);
        assert_eq!(syn.syn_delta, 1);
        assert_eq!(syn.conversation.syn_count, 1);
        assert!(!syn.conversation.established);

        let syn_ack = state.observe(tcp("10.0.0.20", "10.0.0.10", 443, 51000, 0x12, 1.1)).unwrap();
        assert_eq!(syn_ack.direction, ConversationDirection::ToInitiator);
        assert_eq!(syn_ack.syn_ack_delta, 1);
        assert_eq!(syn_ack.conversation.syn_ack_count, 1);
        assert!(syn_ack.conversation.established);

        let rst = state.observe(tcp("10.0.0.10", "10.0.0.20", 51000, 443, 0x04, 1.2)).unwrap();
        assert_eq!(rst.rst_delta, 1);
        assert_eq!(rst.conversation.rst_count, 1);
        assert_eq!(rst.flow.rst_count, 1);
    }

    #[test]
    fn directional_flow_capacity_fails_before_silent_eviction() {
        let mut state = AnalysisState::with_resource_limits(10, 1, 10, 10);
        state.observe(tcp("10.0.0.1", "10.0.0.2", 50000, 80, 0x10, 1.0)).unwrap();
        let error = state.observe(tcp("10.0.0.3", "10.0.0.4", 50001, 443, 0x10, 2.0))
            .expect_err("a second directional flow must cross the negotiated bound");
        assert!(error.contains("directional flow capacity"));
        assert_eq!(state.directional_flows().len(), 1);
    }

    #[test]
    fn observations_intern_stable_endpoint_flow_and_conversation_ids() {
        let mut state = AnalysisState::with_protocol_limits(10, 10, 10, 10, 10);
        let forward = state.observe(tcp("10.0.0.1", "10.0.0.2", 50000, 443, 0x02, 1.0)).unwrap();
        let reverse = state.observe(tcp("10.0.0.2", "10.0.0.1", 443, 50000, 0x12, 2.0)).unwrap();

        assert_ne!(forward.flow_id, reverse.flow_id);
        assert_eq!(forward.conversation_id, reverse.conversation_id);
        assert_eq!(forward.endpoint_definitions.len(), 2);
        assert_eq!(forward.flow_definition.as_ref().unwrap().flow_id, forward.flow_id);
        assert_eq!(forward.conversation_definition.as_ref().unwrap().conversation_id, forward.conversation_id);
        assert!(reverse.endpoint_definitions.is_empty());
        assert!(reverse.conversation_definition.is_none());
    }

    #[test]
    fn endpoint_capacity_is_checked_before_any_state_is_mutated() {
        let mut state = AnalysisState::with_protocol_limits(10, 10, 10, 10, 1);
        let error = state.observe(tcp("10.0.0.1", "10.0.0.2", 50000, 443, 0x02, 1.0))
            .expect_err("two new endpoints exceed a one-endpoint plan");
        assert!(error.contains("endpoint capacity"));
        assert_eq!(state.directional_flows().len(), 0);
        assert_eq!(state.active_conversation_count(), 0);
    }

    #[test]
    fn aggregate_sample_storage_honors_the_negotiated_global_byte_limit() {
        let mut state = AnalysisState::with_sample_byte_limit(10, 10, 10, 10, 10, 24);
        for port in 80..84 {
            state.observe(tcp("10.0.0.1", "10.0.0.2", 50000, port, 0x10, port as f64))
                .unwrap();
        }

        assert_eq!(state.sample_bytes(), 24);
        assert_eq!(
            state.directional_flows().iter().map(|flow| flow.samples.len()).sum::<usize>(),
            2,
        );
    }
}
