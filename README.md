# CA-Verified NFT Marketplace (Proof of Concept)
 
A proof-of-concept NFT marketplace where sellers must complete an identity
verification step before they are allowed to list an asset. Verification is
based on a fingerprint derived from a bipermutative cellular automaton (CA)
rather than a conventional hash function.
 
 
## Why
 
Most "verify before you can sell" flows lean on a
third-party KYC provider. This project instead asks: can a cellular automaton
generate a fingerprint with hash-like properties (diffusion,
avalanche, resistance to trivial collisions) on its own.
## How it works
 
1. **Seller submits identity data** to be verified.
2. **Fingerprint generation.** The data is absorbed into a CA state through a
   sponge-style construction: input is XORed into part of the state
   and a bipermutative CA rule set is applied as the round/permutation
   function between blocks.The fingerprint is squeezed from the final state.
3. **Listing gate.** Only sellers with a verified fingerprint on record can
   list an asset on the marketplace.

 
 
## The fingerprinting scheme
 
- **Primitive:** Bipermutative cellular automaton rules, applied as a
  round function over a fixed-width bit array.
- **Construction:** Sponge-style absorb/squeeze, so the fingerprint size is
  decoupled from the CA width and from the input length.
- **Round constants:** Fixed public constants break the translation symmetry
  a CA has on a ring.
- **Salt:** An optional random per-identity salt, stored alongside the
  fingerprint.
## Known limitations
 
- **Unproven security.** The CA-based fingerprint has not been formally
  analyzed for collision or preimage resistance. Empirical were made, with great results,
  but not sufficient evidence
  of security.
- **Performance.** The CA-based construction is slower than SHA-256 for
  equivalent input sizes.
- **PoC-only trust model.** Marketplace listing/ownership logic is minimal and
  not intended for production use.


## Disclaimer
 
This is an academic/experimental proof of concept. Do not use it to gate
access to real financial assets without an independent security review.
