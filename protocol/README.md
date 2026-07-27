# Protocol

This directory is the canonical source for protocol schemas and cross-client test vectors.

The current schema is **provisional**. Do not treat `0.1.0-dev` as a compatibility promise. ADR-001 and ADR-002 must be accepted before protocol v1 is frozen.

Client repositories vendor a tagged copy of these files and record its SHA-256. They must not depend on a relative path to this repository.
