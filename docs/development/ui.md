# UI Development

The UI is a local V2 workspace backed by the same API projections used by the
CLI. Keep page data bounded, use cursor pagination for large lists, preserve
node/interface/session scope in URLs, and expose processing completeness and
visibility limits instead of implying certainty.

Run the release checks from `ui`:

```bash
npm ci
npm run lint
npm run typecheck
npm run build
```

Keep the existing visual language and make errors actionable with a request ID
and retry path.
