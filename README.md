# siv

A pure Go implementation of of the SIV-CMAC AEAD as described in
RFC 5297. SIV-CMAC does not require a nonce, allowing for both
deterministic and resistance to nonce re- or misuse.
