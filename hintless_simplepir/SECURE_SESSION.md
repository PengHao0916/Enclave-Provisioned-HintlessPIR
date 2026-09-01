# Bounded secure-session flow

The optimized protocol keeps one RLWE secret and one cached Galois key for a
session, but it never reuses a query ciphertext pad. `session_pool_capacity`
sets the number of one-time public components generated during preprocessing.

Use the API in this order:

1. The server calls `Preprocess()` and publishes `GetPublicParams()`.
2. The client calls `GenerateSessionInitRequest()`.
3. The server calls `InitializeSession()` and returns its acknowledgement.
4. The client validates it with `AcceptSessionInitResponse()`.
5. For every query, call `GenerateRequest()`, `HandleRequest()`, and
   `RecoverRecord()` in order.
6. If a request times out, call `AbandonOutstandingRequest()`. The token is
   burned and must not be retransmitted.
7. After a client exhausts its tokens, discard that `Client` and create a new
   session with a fresh client ID and RLWE secret. The same published pool may
   be provisioned to the new session because the `(pad, secret)` pair changes.
   After the database is preprocessed again, obtain the newly versioned pool;
   every session bound to the old version and epoch is invalid.

If session initialization times out before its acknowledgement is validated,
discard that `Client` and start with a fresh client/session ID. Initialization
is deliberately not retried under an ambiguous session state.

The client allows only one outstanding request. Both server layers atomically
enforce a strictly increasing token high-water mark, so replayed and reordered
tokens cannot cause one pad to encrypt two different queries. Requests and
responses are also bound to a client ID, database version, and pool epoch.

`Preprocess()` is a lifecycle operation and must not run concurrently with
online query evaluation. In a multi-process deployment, route a session to one
server process or store its token high-water mark in a shared atomic data store;
independent per-replica counters are unsafe. Use an authenticated transport such
as TLS when the network attacker is outside the semi-honest-server model.
