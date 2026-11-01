# Leaked secret

Goal: stop new use of compromised authority, replace it, preserve attributable
history and prove normal operations use the replacement. Use only dummy
credentials in a drill; never paste a real leaked value into a ticket or log.

## Procedure

1. Identify the affected credential and its authority: API bearer, actor secret,
   provider/bootstrap credential, or master/key-source material. Record the
   version/name and exposure interval, not the plaintext. Preserve access and
   audit evidence privately. An actor secret rotation does not rotate an API
   bearer, KMS credential or master seed.
2. Restrict the affected caller/capability using the actual local administrative
   API socket and current policy. For a compromised API token:

   ```sh
   kronik token list
   kronik token revoke <affected-token-name> --reason 'credential exposure containment'
   ```

   Confirm a new protected request with that old dummy bearer is denied.
   Long-lived streams, queued work and cross-node publication must be tested
   against the final authority implementation; issuing the revoke command
   alone is not proof that every in-flight consumer has stopped.
3. Replace an actor secret through stdin, never argv or shell history:

   ```sh
   printf '%s' 'fixture-only-replacement' | \
     kronik secret set fixture-key --reason 'replace exposed fixture credential'
   ```

   The literal is deliberately a non-secret drill value. In a real incident,
   obtain the replacement through the approved secret input mechanism. Revoke
   the compromised credential at its actual issuer as well; Kronik cannot
   revoke an external provider's credential by changing a local name.
4. Exercise a new real request with the affected actor's normal grant and
   verify it uses the new version/result. Do not grant `secret-reveal` merely
   to prove rotation. Check a known key-backed effect against the fixture's
   expected result and verify the old caller/credential cannot perform a new
   protected operation.
5. Replay retained fixture history with its original immutable recorded
   versions. Retained history/backups may require old key versions; disabling
   them may intentionally make old operations unavailable. Decide that tradeoff
   explicitly, using the provider and retention policies. Do not rewrite old
   SecretRefs, substitute current values for recorded ones, or assume deleting
   a value erases copies already disclosed to another system.
6. Review affected data, recipients and backup lifecycle, then follow the
   [private vulnerability/advisory process](https://github.com/G-man3207/Kronik/security/policy) when a product
   defect is involved. Master-seed exposure needs a separately designed recovery
   and re-encryption procedure: `keys rewrap` changes wrapping custody, not the
   seed, and is not a master-key rotation fix.

## Drill record

Record the owned fixture, exact versions/commands, old/new non-secret version
identities, request results, rejected old-authority request, replay counts and
cleanup. Do not record real bearer/secret bytes. A short local fixture does not
establish provider IAM correctness, human OIDC review, cross-node fencing, or
an unobserved production incident response.
