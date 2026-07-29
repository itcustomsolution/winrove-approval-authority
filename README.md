# Winrove Approval Authority

This public repository contains the digest-only human approval boundary for Winrove staging.

It never receives raw authorizations, organization identifiers, deployment identifiers, source excerpts, credentials, deployment tokens, or production access. A dedicated GitHub App may dispatch one opaque commitment. The protected `winrove-staging-approval` environment requires Fela's review and prevents the dispatcher from approving its own run.

The resulting GitHub OIDC/Sigstore evidence is verified in the private Winrove backend against the original private authorization, a private 256-bit nonce, the exact source commit, expiry, workflow identity, reviewer identity, and the one-use replay ledger.

Production authorization and deployment are outside this repository's scope.
