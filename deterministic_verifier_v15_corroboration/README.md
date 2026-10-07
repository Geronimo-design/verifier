# Deterministic Verifier — Real Dynamic Application

This build is a real local web application, not a scripted example-result UI.
It accepts an incoming claim and an uploaded PDF, extracts the PDF text, computes
an authenticated SHA-256 digest of the source bytes, finds candidate evidence
spans dynamically, and routes every final verdict through one V15 deterministic
adjudication boundary.

## AI role

If `OPENAI_API_KEY` is configured, the application also sends the extracted
claim/document text to the configured OpenAI Responses API model to identify
candidate evidence and semantic properties. The AI output is advisory only and
cannot set or override the verdict.

Default model: `gpt-5.6-luna`.

## Run

1. Install Python 3.11+.
2. In this folder run:
   `python -m pip install -r requirements.txt`
3. Optional AI configuration:
   - copy `.env.example` to `.env` or set environment variables in your shell
   - set `OPENAI_API_KEY`
   - set `OPENAI_MODEL=gpt-5.6-luna` if desired
4. Start:
   `python -m uvicorn app:app --reload`
5. Open http://127.0.0.1:8000
6. Upload any text-based PDF and enter the incoming claim.

## Important fail-closed rule

The app does not manufacture a positive result when evidence is missing. If the
claim cannot be deterministically established from extracted evidence, it returns
UNKNOWN and marks LAWYER CHECK REQUIRED.

## Current scope

- PDF text extraction: implemented.
- Source-byte SHA-256: implemented.
- Dynamic claim input: implemented.
- Dynamic candidate evidence search: implemented.
- V15 deterministic adjudication: implemented as the sole website verdict path.
- Candidate authentication and V15 proof trace: implemented.
- Optional AI candidate extraction: implemented.
- OCR for image-only PDFs: not yet implemented; such PDFs return a clear error.
- Full integration with the protected V15 production artifact: not claimed; this build uses the checked-in V15 working verifier module.

The application no longer contains a second website-level verdict engine. Candidate
discovery remains an application concern, while candidate authentication, proposition
adjudication, contradiction handling, fail-closed outcomes, and final verdict
aggregation are delegated to the V15 verifier entry point.

## V15 application boundary

The website has one application-level V15 dispatcher. Standard, structured semantic,
and structured temporal verification all route to V15; the website does not contain
a second verdict algorithm. AI and heuristic candidate discovery remain advisory and
non-authoritative.

Structured semantic verification requires explicit proposition identity, scope,
polarity, value, cardinality, and evidence metadata. Structured temporal verification
requires explicit temporal endpoints and authenticated temporal evidence bytes.
Missing identity/scope or required corroboration fails closed.

Each verification also receives a verification ID and a JSON audit record under
`audit/`, containing the source digest, engine/version, verdict, reason, and proof trace.

The repository's G01 authority implementation is still explicitly labelled an
implementation candidate rather than a certified production artifact. It is now exposed
through an explicit `authority` application mode for **review-only analysis**. The adapter
authenticates every referenced evidence span through the working V15 evidence boundary,
runs the G01 candidate, records its candidate disposition in the proof trace, and then
hard-gates the public result to `NOT_EVALUATED` until an explicit certification state is
established. Therefore G01 cannot currently produce a production `SUPPORTED` or
`NOT_SUPPORTED` verdict through the website.


## Independent corroboration

The standard V15 application path now accepts multiple PDF evidence sources. Each source is authenticated independently and assigned an identity derived from its SHA-256 content digest. Re-uploading the same document, or uploading byte-identical copies under different filenames, does not create independent corroboration.

A verification may require `required_independent_sources` supporting sources. The cross-source aggregator is fail-closed:

- enough distinct authenticated supporting sources -> `SUPPORTED`;
- supporting and contradicting independent sources -> `UNKNOWN`;
- insufficient independent support -> `UNKNOWN`;
- authenticated source/V15 errors -> `ERROR`.

AI candidate discovery remains advisory only. It cannot create source independence or change a V15 verdict.

Structured semantic, temporal, and authority modes remain single-source for now rather than silently pretending that their structured evidence model supports multi-document aggregation.
