# API

The local API is a FastAPI application served by `tower ui`. Interactive OpenAPI documentation is available from the loopback API's `/docs` route while the service is running.

## Versioning

- `/api/v2` is the canonical API for findings, Behavioral Scoring V2, capture sessions, PCAP jobs, identity, mesh, graph, AI, and authentication.
- `/api/v1` is a compatibility projection for older UI and CLI consumers. New code should not treat legacy entity risk fields as authoritative.

## Common response behavior

- Source, interface, session, and node filters preserve evidence scope.
- Large collections use bounded limits and cursor pagination.
- Errors include a stable code, concise operator message, and request ID.
- Long-running operations expose state and progress rather than claiming immediate completion.
- Capture stop returns a draining state until final acknowledgements arrive.
- Partial processing is represented explicitly.

## Principal resource families

```text
/api/v2/dashboard/summary
/api/v2/flows
/api/v2/findings
/api/v2/alerts
/api/v2/risk/entities
/api/v2/pipeline/health
/api/v2/captures
/api/v2/pcap/analyses
/api/v2/identity
/api/v2/endpoint
/api/v2/plugins
/api/v2/scoring
/api/v2/mesh
/api/v2/graph
/api/v2/ai
/api/v2/auth
```

Use OpenAPI as the field-level contract. Avoid duplicating business logic in API handlers; handlers should validate requests, call services/repositories, and project typed results.

## SSE

PCAP analysis and AI runs expose server-sent event streams. Events are resumable by run/job identity, bounded, and terminal states remain queryable after the stream closes. Clients must still fetch the terminal resource because stream disconnection is not proof of cancellation or failure.

## Authentication

Browser sessions use host-only, HttpOnly, SameSite=Strict cookies and origin-bound challenges. CLI sessions use installation-bound OS credential storage. Highly sensitive endpoints require recent step-up proof without extending the eight-hour main session.

## Adding an endpoint

1. Add request/response schemas under `core/api/schemas.py`.
2. Put behavior in an owning service or repository.
3. Preserve provenance and processing completeness.
4. Enforce bounded limits and opaque cursors for collections.
5. Add request-ID-aware errors.
6. Test success, invalid input, empty state, authorization, partial state, and storage failure.
7. Update the UI client and this resource-family overview when the endpoint is public.
