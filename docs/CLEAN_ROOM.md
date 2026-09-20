# Clean-room development policy

GANJ VPS is an independent implementation.

## Rules

1. Product behavior and public interoperability may be studied from public documentation, public APIs, and observable behavior.
2. Third-party source code is not copied into GANJ VPS.
3. Third-party branding, artwork, documentation text, screenshots, and private assets are not reused.
4. GANJ source files use GANJ naming, data models, protocols, UI language, architecture, and implementation.
5. Panel integration targets public/local APIs of software installed by the server owner.
6. Before adding a third-party dependency or vendored component, its license must be recorded and respected.
7. Secrets from customer panels remain on the customer node unless a feature explicitly requires otherwise; current panel adapters keep those credentials local.

This file documents the project process; it is not a statement about the licensing terms of unrelated projects.
