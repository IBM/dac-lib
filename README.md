# Delegatable Anonymous Credentials Library

This is the Go implementation of the Delegatable Anonymous Credentials (DAC) library presented in [Anonymous Transactions with Revocation and Auditing in Hyperledger Fabric](https://eprint.iacr.org/2019/1097.pdf) (with base protocol first introduced in [Practical UC-secure delegatable credentials with attributes and their application to blockchain](https://acmccs.github.io/papers/p683-camenischA.pdf)).
Hereafter, the references are made to [Anonymous Transactions with Revocation and Auditing in Hyperledger Fabric](https://eprint.iacr.org/2019/1097.pdf).

This work has been supported in part by the European Union's Horizon 2020 research and innovation programme under grant agreement No. 780477 PRIViLEDGE.
The publication has appeared in CANS 2021.
This work should be cited as

<!-- TODO: add DOI and volume -->

> Bogatov D., De Caro A., Elkhiyaoui K., Tackmann B. (2021) Anonymous Transactions with Revocation and Auditing in Hyperledger Fabric. In: Krenn S., Conti M., Stevens M. (eds) Cryptology and Network Security. CANS 2021. Lecture Notes in Computer Science. Springer, Cham.

<details>
 <summary>or with bibtex</summary>

```tex
@inproceedings{dac-revocation-auditing,
  author       = {Dmytro Bogatov and Angelo De Caro and Kaoutar Elkhiyaoui and Björn Tackmann},
  editor       = {Stephan Krenn and Mauro Conti and Marc Stevens},
  title        = {Anonymous Transactions with Revocation and Auditing in Hyperledger Fabric},
  year         = {2021},
  publisher    = {Springer International Publishing}
}
```

</details>

## What's implemented

This library is implemented as a Go 13 module with over 470 tests.
The documentation is automatically generate on pkg.go.dev: [dbogatov/dac-lib](https://pkg.go.dev/github.com/dbogatov/dac-lib).

On a high level, here is the API (al objects can be marshalled).

- Schnorr signatures (the signature object key generation, signing, verifying and marshalling routines) are in `schnorr.go`.
The mechanism works for both groups $`\mathbb{G}_1`$ and $`\mathbb{G}_2`$.

- Groth signatures (the signature object key generation, signing, randomizing, verifying and marshalling routines) are in `groth.go`.
The mechanism works for both groups $`\mathbb{G}_1`$ and $`\mathbb{G}_2`$.

- Sibling signatures is a wrapper around Schnorr and Groth to be used in DAC itself, see `siblings.go`.

- `scheme.go` has routines to generate empty credentials, extending them by delegation, verifying the credentials, generating a proof of these credentials and verifying the proof.
Generating and verifying proof is in Algorithm 6 in the [paper](https://eprint.iacr.org/2019/1097.pdf).

- `revocation.go` has routines to generate a proof of non-revocation and verify it, see Algorithm 4 in the [paper](https://eprint.iacr.org/2019/1097.pdf).

- `auditing.go` has routines to generate an encryption, decrypt it, generate the proof and verify it, see Algorithm 5 in the [paper](https://eprint.iacr.org/2019/1097.pdf).

- `pseudonym.go` manipulates pseudonyms (Algorithm 3 in the [paper](https://eprint.iacr.org/2019/1097.pdf)), `credrequest.go` hasa secure way to request a credential and `util.go` has the helpers.

- See `TestHappyPath` in `scheme_test.go` for the end-to-end example of creating credentials, revoking and auditing and manipulating marshalled objects.

## How to run the tests

Quite simple: `go test ./dac/ -v`

<details>
 <summary>sample output</summary>

```
=== RUN   TestAuditing
=== RUN   TestAuditing/h_in_g1
=== RUN   TestAuditing/h_in_g1/test_auditing_happy_path
=== RUN   TestAuditing/h_in_g1/test_auditing_decryption_fail
=== RUN   TestAuditing/h_in_g1/test_auditing_verification_fail
=== RUN   TestAuditing/h_in_g1/test_auditing_marshal
=== RUN   TestAuditing/h_in_g1/test_auditing_encryption_un_marshal_fails
=== RUN   TestAuditing/h_in_g1/test_auditing_proof_un_marshal_fails
=== RUN   TestAuditing/h_in_g2
=== RUN   TestAuditing/h_in_g2/test_auditing_happy_path
=== RUN   TestAuditing/h_in_g2/test_auditing_decryption_fail
=== RUN   TestAuditing/h_in_g2/test_auditing_verification_fail
=== RUN   TestAuditing/h_in_g2/test_auditing_marshal
=== RUN   TestAuditing/h_in_g2/test_auditing_encryption_un_marshal_fails
=== RUN   TestAuditing/h_in_g2/test_auditing_proof_un_marshal_fails
--- PASS: TestAuditing (0.48s)
    --- PASS: TestAuditing/h_in_g1 (0.11s)
        --- PASS: TestAuditing/h_in_g1/test_auditing_happy_path (0.03s)
        --- PASS: TestAuditing/h_in_g1/test_auditing_decryption_fail (0.01s)
        --- PASS: TestAuditing/h_in_g1/test_auditing_verification_fail (0.03s)
        --- PASS: TestAuditing/h_in_g1/test_auditing_marshal (0.04s)
        --- PASS: TestAuditing/h_in_g1/test_auditing_encryption_un_marshal_fails (0.00s)
        --- PASS: TestAuditing/h_in_g1/test_auditing_proof_un_marshal_fails (0.00s)
    --- PASS: TestAuditing/h_in_g2 (0.37s)
        --- PASS: TestAuditing/h_in_g2/test_auditing_happy_path (0.10s)
        --- PASS: TestAuditing/h_in_g2/test_auditing_decryption_fail (0.03s)
        --- PASS: TestAuditing/h_in_g2/test_auditing_verification_fail (0.11s)
        --- PASS: TestAuditing/h_in_g2/test_auditing_marshal (0.13s)
        --- PASS: TestAuditing/h_in_g2/test_auditing_encryption_un_marshal_fails (0.00s)
        --- PASS: TestAuditing/h_in_g2/test_auditing_proof_un_marshal_fails (0.00s)
=== RUN   TestCredRequest
=== RUN   TestCredRequest/l=1
=== RUN   TestCredRequest/l=1/test_cred_request_make_no_crash
=== RUN   TestCredRequest/l=1/test_cred_request_make_deterministic
=== RUN   TestCredRequest/l=1/test_cred_request_make_randomized
=== RUN   TestCredRequest/l=1/test_cred_request_equality
=== RUN   TestCredRequest/l=1/test_cred_request_equality/correct
=== RUN   TestCredRequest/l=1/test_cred_request_equality/wrong_nonce
=== RUN   TestCredRequest/l=1/test_cred_request_equality/wrong_nonce_length
=== RUN   TestCredRequest/l=1/test_cred_request_equality/wrong_resR
=== RUN   TestCredRequest/l=1/test_cred_request_equality/wrong_resT
=== RUN   TestCredRequest/l=1/test_cred_request_equality/wrong_public_key
=== RUN   TestCredRequest/l=1/test_cred_request_validate_no_crash
=== RUN   TestCredRequest/l=1/test_cred_request_validate_correct
=== RUN   TestCredRequest/l=1/test_cred_request_validate_tampered
=== RUN   TestCredRequest/l=1/test_cred_request_validate_tampered/wrong_nonce
=== RUN   TestCredRequest/l=1/test_cred_request_validate_tampered/wrong_resR
=== RUN   TestCredRequest/l=1/test_cred_request_validate_tampered/wrong_resT
=== RUN   TestCredRequest/l=1/test_cred_request_validate_tampered/wrong_public_key
=== RUN   TestCredRequest/l=1/test_cred_request_marshaling
=== RUN   TestCredRequest/l=1/test_cred_request_un_marshaling_fail
=== RUN   TestCredRequest/l=2
=== RUN   TestCredRequest/l=2/test_cred_request_make_no_crash
=== RUN   TestCredRequest/l=2/test_cred_request_make_deterministic
=== RUN   TestCredRequest/l=2/test_cred_request_make_randomized
=== RUN   TestCredRequest/l=2/test_cred_request_equality
=== RUN   TestCredRequest/l=2/test_cred_request_equality/correct
=== RUN   TestCredRequest/l=2/test_cred_request_equality/wrong_nonce
=== RUN   TestCredRequest/l=2/test_cred_request_equality/wrong_nonce_length
=== RUN   TestCredRequest/l=2/test_cred_request_equality/wrong_resR
=== RUN   TestCredRequest/l=2/test_cred_request_equality/wrong_resT
=== RUN   TestCredRequest/l=2/test_cred_request_equality/wrong_public_key
=== RUN   TestCredRequest/l=2/test_cred_request_validate_no_crash
=== RUN   TestCredRequest/l=2/test_cred_request_validate_correct
=== RUN   TestCredRequest/l=2/test_cred_request_validate_tampered
=== RUN   TestCredRequest/l=2/test_cred_request_validate_tampered/wrong_nonce
=== RUN   TestCredRequest/l=2/test_cred_request_validate_tampered/wrong_resR
=== RUN   TestCredRequest/l=2/test_cred_request_validate_tampered/wrong_resT
=== RUN   TestCredRequest/l=2/test_cred_request_validate_tampered/wrong_public_key
=== RUN   TestCredRequest/l=2/test_cred_request_marshaling
=== RUN   TestCredRequest/l=2/test_cred_request_un_marshaling_fail
--- PASS: TestCredRequest (0.59s)
    --- PASS: TestCredRequest/l=1 (0.16s)
        --- PASS: TestCredRequest/l=1/test_cred_request_make_no_crash (0.01s)
        --- PASS: TestCredRequest/l=1/test_cred_request_make_deterministic (0.01s)
        --- PASS: TestCredRequest/l=1/test_cred_request_make_randomized (0.01s)
        --- PASS: TestCredRequest/l=1/test_cred_request_equality (0.07s)
            --- PASS: TestCredRequest/l=1/test_cred_request_equality/correct (0.01s)
            --- PASS: TestCredRequest/l=1/test_cred_request_equality/wrong_nonce (0.01s)
            --- PASS: TestCredRequest/l=1/test_cred_request_equality/wrong_nonce_length (0.01s)
            --- PASS: TestCredRequest/l=1/test_cred_request_equality/wrong_resR (0.01s)
            --- PASS: TestCredRequest/l=1/test_cred_request_equality/wrong_resT (0.01s)
            --- PASS: TestCredRequest/l=1/test_cred_request_equality/wrong_public_key (0.01s)
        --- PASS: TestCredRequest/l=1/test_cred_request_validate_no_crash (0.01s)
        --- PASS: TestCredRequest/l=1/test_cred_request_validate_correct (0.01s)
        --- PASS: TestCredRequest/l=1/test_cred_request_validate_tampered (0.04s)
            --- PASS: TestCredRequest/l=1/test_cred_request_validate_tampered/wrong_nonce (0.01s)
            --- PASS: TestCredRequest/l=1/test_cred_request_validate_tampered/wrong_resR (0.01s)
            --- PASS: TestCredRequest/l=1/test_cred_request_validate_tampered/wrong_resT (0.01s)
            --- PASS: TestCredRequest/l=1/test_cred_request_validate_tampered/wrong_public_key (0.01s)
        --- PASS: TestCredRequest/l=1/test_cred_request_marshaling (0.01s)
        --- PASS: TestCredRequest/l=1/test_cred_request_un_marshaling_fail (0.00s)
    --- PASS: TestCredRequest/l=2 (0.43s)
        --- PASS: TestCredRequest/l=2/test_cred_request_make_no_crash (0.02s)
        --- PASS: TestCredRequest/l=2/test_cred_request_make_deterministic (0.04s)
        --- PASS: TestCredRequest/l=2/test_cred_request_make_randomized (0.03s)
        --- PASS: TestCredRequest/l=2/test_cred_request_equality (0.16s)
            --- PASS: TestCredRequest/l=2/test_cred_request_equality/correct (0.03s)
            --- PASS: TestCredRequest/l=2/test_cred_request_equality/wrong_nonce (0.03s)
            --- PASS: TestCredRequest/l=2/test_cred_request_equality/wrong_nonce_length (0.03s)
            --- PASS: TestCredRequest/l=2/test_cred_request_equality/wrong_resR (0.02s)
            --- PASS: TestCredRequest/l=2/test_cred_request_equality/wrong_resT (0.03s)
            --- PASS: TestCredRequest/l=2/test_cred_request_equality/wrong_public_key (0.02s)
        --- PASS: TestCredRequest/l=2/test_cred_request_validate_no_crash (0.03s)
        --- PASS: TestCredRequest/l=2/test_cred_request_validate_correct (0.03s)
        --- PASS: TestCredRequest/l=2/test_cred_request_validate_tampered (0.10s)
            --- PASS: TestCredRequest/l=2/test_cred_request_validate_tampered/wrong_nonce (0.02s)
            --- PASS: TestCredRequest/l=2/test_cred_request_validate_tampered/wrong_resR (0.02s)
            --- PASS: TestCredRequest/l=2/test_cred_request_validate_tampered/wrong_resT (0.03s)
            --- PASS: TestCredRequest/l=2/test_cred_request_validate_tampered/wrong_public_key (0.03s)
        --- PASS: TestCredRequest/l=2/test_cred_request_marshaling (0.02s)
        --- PASS: TestCredRequest/l=2/test_cred_request_un_marshaling_fail (0.00s)
=== RUN   TestGroth
=== RUN   TestGroth/b=1
=== RUN   TestGroth/b=1/test_groth_consistency_checks
=== RUN   TestGroth/b=1/test_groth_consistency_checks/wrong_message_for_sign
=== RUN   TestGroth/b=1/test_groth_consistency_checks/wrong_ts_for_randomize
=== RUN   TestGroth/b=1/test_groth_consistency_checks/wrong_m_and_ts_for_verify
=== RUN   TestGroth/b=1/test_groth_deterministic_generate
=== RUN   TestGroth/b=1/test_groth_randomize_different_seed
=== RUN   TestGroth/b=1/test_groth_randomize_no_crash
=== RUN   TestGroth/b=1/test_groth_randomize_same_seed
=== RUN   TestGroth/b=1/test_groth_randomized_generate
=== RUN   TestGroth/b=1/test_groth_sign_no_crash
=== RUN   TestGroth/b=1/test_groth_signature_working_after_randomization
=== RUN   TestGroth/b=1/test_groth_verify_correct
=== RUN   TestGroth/b=1/test_groth_verify_tampered_signature
=== RUN   TestGroth/b=1/test_groth_verify_wrong_message
=== RUN   TestGroth/b=1/test_groth_verify_no_crash
=== RUN   TestGroth/b=1/test_groth_signature_equality
=== RUN   TestGroth/b=1/test_groth_signature_equality/correct
=== RUN   TestGroth/b=1/test_groth_signature_equality/wrong_r
=== RUN   TestGroth/b=1/test_groth_signature_equality/wrong_s
=== RUN   TestGroth/b=1/test_groth_signature_equality/wrong_ts
=== RUN   TestGroth/b=1/test_groth_signature_marshal
=== RUN   TestGroth/b=1/test_groth_signature_un_marshal_fails
=== RUN   TestGroth/b=2
=== RUN   TestGroth/b=2/test_groth_consistency_checks
=== RUN   TestGroth/b=2/test_groth_consistency_checks/wrong_message_for_sign
=== RUN   TestGroth/b=2/test_groth_consistency_checks/wrong_ts_for_randomize
=== RUN   TestGroth/b=2/test_groth_consistency_checks/wrong_m_and_ts_for_verify
=== RUN   TestGroth/b=2/test_groth_deterministic_generate
=== RUN   TestGroth/b=2/test_groth_randomize_different_seed
=== RUN   TestGroth/b=2/test_groth_randomize_no_crash
=== RUN   TestGroth/b=2/test_groth_randomize_same_seed
=== RUN   TestGroth/b=2/test_groth_randomized_generate
=== RUN   TestGroth/b=2/test_groth_sign_no_crash
=== RUN   TestGroth/b=2/test_groth_signature_working_after_randomization
=== RUN   TestGroth/b=2/test_groth_verify_correct
=== RUN   TestGroth/b=2/test_groth_verify_tampered_signature
=== RUN   TestGroth/b=2/test_groth_verify_wrong_message
=== RUN   TestGroth/b=2/test_groth_verify_no_crash
=== RUN   TestGroth/b=2/test_groth_signature_equality
=== RUN   TestGroth/b=2/test_groth_signature_equality/correct
=== RUN   TestGroth/b=2/test_groth_signature_equality/wrong_r
=== RUN   TestGroth/b=2/test_groth_signature_equality/wrong_s
=== RUN   TestGroth/b=2/test_groth_signature_equality/wrong_ts
=== RUN   TestGroth/b=2/test_groth_signature_marshal
=== RUN   TestGroth/b=2/test_groth_signature_un_marshal_fails
--- PASS: TestGroth (2.27s)
    --- PASS: TestGroth/b=1 (0.90s)
        --- PASS: TestGroth/b=1/test_groth_consistency_checks (0.03s)
            --- PASS: TestGroth/b=1/test_groth_consistency_checks/wrong_message_for_sign (0.00s)
            --- PASS: TestGroth/b=1/test_groth_consistency_checks/wrong_ts_for_randomize (0.00s)
            --- PASS: TestGroth/b=1/test_groth_consistency_checks/wrong_m_and_ts_for_verify (0.00s)
        --- PASS: TestGroth/b=1/test_groth_deterministic_generate (0.02s)
        --- PASS: TestGroth/b=1/test_groth_randomize_different_seed (0.05s)
        --- PASS: TestGroth/b=1/test_groth_randomize_no_crash (0.04s)
        --- PASS: TestGroth/b=1/test_groth_randomize_same_seed (0.03s)
        --- PASS: TestGroth/b=1/test_groth_randomized_generate (0.01s)
        --- PASS: TestGroth/b=1/test_groth_sign_no_crash (0.02s)
        --- PASS: TestGroth/b=1/test_groth_signature_working_after_randomization (0.09s)
        --- PASS: TestGroth/b=1/test_groth_verify_correct (0.08s)
        --- PASS: TestGroth/b=1/test_groth_verify_tampered_signature (0.09s)
        --- PASS: TestGroth/b=1/test_groth_verify_wrong_message (0.09s)
        --- PASS: TestGroth/b=1/test_groth_verify_no_crash (0.08s)
        --- PASS: TestGroth/b=1/test_groth_signature_equality (0.24s)
            --- PASS: TestGroth/b=1/test_groth_signature_equality/correct (0.06s)
            --- PASS: TestGroth/b=1/test_groth_signature_equality/wrong_r (0.06s)
            --- PASS: TestGroth/b=1/test_groth_signature_equality/wrong_s (0.06s)
            --- PASS: TestGroth/b=1/test_groth_signature_equality/wrong_ts (0.06s)
        --- PASS: TestGroth/b=1/test_groth_signature_marshal (0.02s)
        --- PASS: TestGroth/b=1/test_groth_signature_un_marshal_fails (0.00s)
    --- PASS: TestGroth/b=2 (1.32s)
        --- PASS: TestGroth/b=2/test_groth_consistency_checks (0.06s)
            --- PASS: TestGroth/b=2/test_groth_consistency_checks/wrong_message_for_sign (0.00s)
            --- PASS: TestGroth/b=2/test_groth_consistency_checks/wrong_ts_for_randomize (0.00s)
            --- PASS: TestGroth/b=2/test_groth_consistency_checks/wrong_m_and_ts_for_verify (0.00s)
        --- PASS: TestGroth/b=2/test_groth_deterministic_generate (0.03s)
        --- PASS: TestGroth/b=2/test_groth_randomize_different_seed (0.08s)
        --- PASS: TestGroth/b=2/test_groth_randomize_no_crash (0.08s)
        --- PASS: TestGroth/b=2/test_groth_randomize_same_seed (0.07s)
        --- PASS: TestGroth/b=2/test_groth_randomized_generate (0.00s)
        --- PASS: TestGroth/b=2/test_groth_sign_no_crash (0.04s)
        --- PASS: TestGroth/b=2/test_groth_signature_working_after_randomization (0.10s)
        --- PASS: TestGroth/b=2/test_groth_verify_correct (0.10s)
        --- PASS: TestGroth/b=2/test_groth_verify_tampered_signature (0.09s)
        --- PASS: TestGroth/b=2/test_groth_verify_wrong_message (0.10s)
        --- PASS: TestGroth/b=2/test_groth_verify_no_crash (0.10s)
        --- PASS: TestGroth/b=2/test_groth_signature_equality (0.42s)
            --- PASS: TestGroth/b=2/test_groth_signature_equality/correct (0.11s)
            --- PASS: TestGroth/b=2/test_groth_signature_equality/wrong_r (0.10s)
            --- PASS: TestGroth/b=2/test_groth_signature_equality/wrong_s (0.11s)
            --- PASS: TestGroth/b=2/test_groth_signature_equality/wrong_ts (0.11s)
        --- PASS: TestGroth/b=2/test_groth_signature_marshal (0.04s)
        --- PASS: TestGroth/b=2/test_groth_signature_un_marshal_fails (0.00s)
=== RUN   TestNoIdemix
=== RUN   TestNoIdemix/ecdsa_standard_P224
=== RUN   TestNoIdemix/ecdsa_standard_P256
=== RUN   TestNoIdemix/ecdsa_standard_P384
=== RUN   TestNoIdemix/ecdsa_standard_P521
--- PASS: TestNoIdemix (0.03s)
    --- PASS: TestNoIdemix/ecdsa_standard_P224 (0.00s)
    --- PASS: TestNoIdemix/ecdsa_standard_P256 (0.00s)
    --- PASS: TestNoIdemix/ecdsa_standard_P384 (0.02s)
    --- PASS: TestNoIdemix/ecdsa_standard_P521 (0.01s)
=== RUN   TestNym
=== RUN   TestNym/h_in_g1
=== RUN   TestNym/h_in_g1/test_nym_deterministic_generate
=== RUN   TestNym/h_in_g1/test_nym_equality
=== RUN   TestNym/h_in_g1/test_nym_equality/correct
=== RUN   TestNym/h_in_g1/test_nym_equality/wrong_resSk
=== RUN   TestNym/h_in_g1/test_nym_equality/wrong_resSkNym
=== RUN   TestNym/h_in_g1/test_nym_equality/wrong_commitment
=== RUN   TestNym/h_in_g1/test_nym_marshal
=== RUN   TestNym/h_in_g1/test_nym_randomized_generate
=== RUN   TestNym/h_in_g1/test_nym_sign_no_crash
=== RUN   TestNym/h_in_g1/test_nym_verify_correct
=== RUN   TestNym/h_in_g1/test_nym_verify_no_crash
=== RUN   TestNym/h_in_g1/test_nym_verify_tampered_signature
=== RUN   TestNym/h_in_g1/test_nym_verify_tampered_signature/wrong_resSk
=== RUN   TestNym/h_in_g1/test_nym_verify_tampered_signature/wrong_resSkNym
=== RUN   TestNym/h_in_g1/test_nym_verify_tampered_signature/wrong_commitment
=== RUN   TestNym/h_in_g1/test_nym_verify_wrong_message
=== RUN   TestNym/h_in_g1/test_nym_un_marshaling_fail
=== RUN   TestNym/h_in_g2
=== RUN   TestNym/h_in_g2/test_nym_deterministic_generate
=== RUN   TestNym/h_in_g2/test_nym_equality
=== RUN   TestNym/h_in_g2/test_nym_equality/correct
=== RUN   TestNym/h_in_g2/test_nym_equality/wrong_resSk
=== RUN   TestNym/h_in_g2/test_nym_equality/wrong_resSkNym
=== RUN   TestNym/h_in_g2/test_nym_equality/wrong_commitment
=== RUN   TestNym/h_in_g2/test_nym_marshal
=== RUN   TestNym/h_in_g2/test_nym_randomized_generate
=== RUN   TestNym/h_in_g2/test_nym_sign_no_crash
=== RUN   TestNym/h_in_g2/test_nym_verify_correct
=== RUN   TestNym/h_in_g2/test_nym_verify_no_crash
=== RUN   TestNym/h_in_g2/test_nym_verify_tampered_signature
=== RUN   TestNym/h_in_g2/test_nym_verify_tampered_signature/wrong_resSk
=== RUN   TestNym/h_in_g2/test_nym_verify_tampered_signature/wrong_resSkNym
=== RUN   TestNym/h_in_g2/test_nym_verify_tampered_signature/wrong_commitment
=== RUN   TestNym/h_in_g2/test_nym_verify_wrong_message
=== RUN   TestNym/h_in_g2/test_nym_un_marshaling_fail
--- PASS: TestNym (0.80s)
    --- PASS: TestNym/h_in_g1 (0.23s)
        --- PASS: TestNym/h_in_g1/test_nym_deterministic_generate (0.01s)
        --- PASS: TestNym/h_in_g1/test_nym_equality (0.07s)
            --- PASS: TestNym/h_in_g1/test_nym_equality/correct (0.02s)
            --- PASS: TestNym/h_in_g1/test_nym_equality/wrong_resSk (0.02s)
            --- PASS: TestNym/h_in_g1/test_nym_equality/wrong_resSkNym (0.02s)
            --- PASS: TestNym/h_in_g1/test_nym_equality/wrong_commitment (0.02s)
        --- PASS: TestNym/h_in_g1/test_nym_marshal (0.01s)
        --- PASS: TestNym/h_in_g1/test_nym_randomized_generate (0.01s)
        --- PASS: TestNym/h_in_g1/test_nym_sign_no_crash (0.01s)
        --- PASS: TestNym/h_in_g1/test_nym_verify_correct (0.02s)
        --- PASS: TestNym/h_in_g1/test_nym_verify_no_crash (0.02s)
        --- PASS: TestNym/h_in_g1/test_nym_verify_tampered_signature (0.05s)
            --- PASS: TestNym/h_in_g1/test_nym_verify_tampered_signature/wrong_resSk (0.02s)
            --- PASS: TestNym/h_in_g1/test_nym_verify_tampered_signature/wrong_resSkNym (0.02s)
            --- PASS: TestNym/h_in_g1/test_nym_verify_tampered_signature/wrong_commitment (0.02s)
        --- PASS: TestNym/h_in_g1/test_nym_verify_wrong_message (0.02s)
        --- PASS: TestNym/h_in_g1/test_nym_un_marshaling_fail (0.00s)
    --- PASS: TestNym/h_in_g2 (0.56s)
        --- PASS: TestNym/h_in_g2/test_nym_deterministic_generate (0.03s)
        --- PASS: TestNym/h_in_g2/test_nym_equality (0.17s)
            --- PASS: TestNym/h_in_g2/test_nym_equality/correct (0.04s)
            --- PASS: TestNym/h_in_g2/test_nym_equality/wrong_resSk (0.04s)
            --- PASS: TestNym/h_in_g2/test_nym_equality/wrong_resSkNym (0.04s)
            --- PASS: TestNym/h_in_g2/test_nym_equality/wrong_commitment (0.04s)
        --- PASS: TestNym/h_in_g2/test_nym_marshal (0.03s)
        --- PASS: TestNym/h_in_g2/test_nym_randomized_generate (0.03s)
        --- PASS: TestNym/h_in_g2/test_nym_sign_no_crash (0.03s)
        --- PASS: TestNym/h_in_g2/test_nym_verify_correct (0.04s)
        --- PASS: TestNym/h_in_g2/test_nym_verify_no_crash (0.06s)
        --- PASS: TestNym/h_in_g2/test_nym_verify_tampered_signature (0.13s)
            --- PASS: TestNym/h_in_g2/test_nym_verify_tampered_signature/wrong_resSk (0.04s)
            --- PASS: TestNym/h_in_g2/test_nym_verify_tampered_signature/wrong_resSkNym (0.04s)
            --- PASS: TestNym/h_in_g2/test_nym_verify_tampered_signature/wrong_commitment (0.05s)
        --- PASS: TestNym/h_in_g2/test_nym_verify_wrong_message (0.05s)
        --- PASS: TestNym/h_in_g2/test_nym_un_marshaling_fail (0.00s)
=== RUN   TestRevocation
=== RUN   TestRevocation/h_in_g1
=== RUN   TestRevocation/h_in_g1/test_revocation_happy_path
=== RUN   TestRevocation/h_in_g1/test_revocation_verification_fails_early
=== RUN   TestRevocation/h_in_g1/test_revocation_verification_fails_later
=== RUN   TestRevocation/h_in_g1/test_revocation_marshal
=== RUN   TestRevocation/h_in_g1/test_revocation_un_marshal_fails
=== RUN   TestRevocation/h_in_g2
=== RUN   TestRevocation/h_in_g2/test_revocation_happy_path
=== RUN   TestRevocation/h_in_g2/test_revocation_verification_fails_early
=== RUN   TestRevocation/h_in_g2/test_revocation_verification_fails_later
=== RUN   TestRevocation/h_in_g2/test_revocation_marshal
=== RUN   TestRevocation/h_in_g2/test_revocation_un_marshal_fails
--- PASS: TestRevocation (2.34s)
    --- PASS: TestRevocation/h_in_g1 (1.31s)
        --- PASS: TestRevocation/h_in_g1/test_revocation_happy_path (0.37s)
        --- PASS: TestRevocation/h_in_g1/test_revocation_verification_fails_early (0.26s)
        --- PASS: TestRevocation/h_in_g1/test_revocation_verification_fails_later (0.35s)
        --- PASS: TestRevocation/h_in_g1/test_revocation_marshal (0.33s)
        --- PASS: TestRevocation/h_in_g1/test_revocation_un_marshal_fails (0.00s)
    --- PASS: TestRevocation/h_in_g2 (1.04s)
        --- PASS: TestRevocation/h_in_g2/test_revocation_happy_path (0.29s)
        --- PASS: TestRevocation/h_in_g2/test_revocation_verification_fails_early (0.19s)
        --- PASS: TestRevocation/h_in_g2/test_revocation_verification_fails_later (0.29s)
        --- PASS: TestRevocation/h_in_g2/test_revocation_marshal (0.28s)
        --- PASS: TestRevocation/h_in_g2/test_revocation_un_marshal_fails (0.00s)
=== RUN   TestHappyPath
--- PASS: TestHappyPath (0.56s)
=== RUN   TestSchemeDelegateNoCrash
--- PASS: TestSchemeDelegateNoCrash (0.16s)
=== RUN   TestSchemeVerifyNoCrash
--- PASS: TestSchemeVerifyNoCrash (0.27s)
=== RUN   TestSchemeVerifyCorrect
=== RUN   TestSchemeVerifyCorrect/L=1
=== RUN   TestSchemeVerifyCorrect/L=2
=== RUN   TestSchemeVerifyCorrect/L=3
=== RUN   TestSchemeVerifyCorrect/L=5
=== RUN   TestSchemeVerifyCorrect/L=10
--- PASS: TestSchemeVerifyCorrect (2.17s)
    --- PASS: TestSchemeVerifyCorrect/L=1 (0.14s)
    --- PASS: TestSchemeVerifyCorrect/L=2 (0.25s)
    --- PASS: TestSchemeVerifyCorrect/L=3 (0.33s)
    --- PASS: TestSchemeVerifyCorrect/L=5 (0.47s)
    --- PASS: TestSchemeVerifyCorrect/L=10 (0.97s)
=== RUN   TestSchemeVerifyTamperedCreds
=== RUN   TestSchemeVerifyTamperedCreds/wrong_public_key
=== RUN   TestSchemeVerifyTamperedCreds/wrong_secret_key
=== RUN   TestSchemeVerifyTamperedCreds/wrong_credentials_link
--- PASS: TestSchemeVerifyTamperedCreds (0.81s)
    --- PASS: TestSchemeVerifyTamperedCreds/wrong_public_key (0.17s)
    --- PASS: TestSchemeVerifyTamperedCreds/wrong_secret_key (0.32s)
    --- PASS: TestSchemeVerifyTamperedCreds/wrong_credentials_link (0.32s)
=== RUN   TestSchemeProveNoCrash
--- PASS: TestSchemeProveNoCrash (0.39s)
=== RUN   TestSchemeProveDeterministic
--- PASS: TestSchemeProveDeterministic (0.79s)
=== RUN   TestSchemeProveRandomized
--- PASS: TestSchemeProveRandomized (0.83s)
=== RUN   TestSchemeVerifyProofNoCrash
--- PASS: TestSchemeVerifyProofNoCrash (0.54s)
=== RUN   TestSchemeVerifyProofCorrect
=== RUN   TestSchemeVerifyProofCorrect/L=1
=== RUN   TestSchemeVerifyProofCorrect/L=2
=== RUN   TestSchemeVerifyProofCorrect/L=3
=== RUN   TestSchemeVerifyProofCorrect/L=5
=== RUN   TestSchemeVerifyProofCorrect/L=10
=== RUN   TestSchemeVerifyProofCorrect/disclosed_level=1
=== RUN   TestSchemeVerifyProofCorrect/disclosed_level=2
=== RUN   TestSchemeVerifyProofCorrect/disclosed_level=3
=== RUN   TestSchemeVerifyProofCorrect/disclosed_level=4
=== RUN   TestSchemeVerifyProofCorrect/disclosed_level=5
=== RUN   TestSchemeVerifyProofCorrect/all_disclosed
=== RUN   TestSchemeVerifyProofCorrect/all_hidden
--- PASS: TestSchemeVerifyProofCorrect (10.87s)
    --- PASS: TestSchemeVerifyProofCorrect/L=1 (0.21s)
    --- PASS: TestSchemeVerifyProofCorrect/L=2 (0.42s)
    --- PASS: TestSchemeVerifyProofCorrect/L=3 (0.53s)
    --- PASS: TestSchemeVerifyProofCorrect/L=5 (0.93s)
    --- PASS: TestSchemeVerifyProofCorrect/L=10 (1.92s)
    --- PASS: TestSchemeVerifyProofCorrect/disclosed_level=1 (0.91s)
    --- PASS: TestSchemeVerifyProofCorrect/disclosed_level=2 (0.91s)
    --- PASS: TestSchemeVerifyProofCorrect/disclosed_level=3 (0.91s)
    --- PASS: TestSchemeVerifyProofCorrect/disclosed_level=4 (0.89s)
    --- PASS: TestSchemeVerifyProofCorrect/disclosed_level=5 (1.08s)
    --- PASS: TestSchemeVerifyProofCorrect/all_disclosed (1.08s)
    --- PASS: TestSchemeVerifyProofCorrect/all_hidden (1.07s)
=== RUN   TestSchemeVerifyProofTampered
=== RUN   TestSchemeVerifyProofTampered/l=1
=== RUN   TestSchemeVerifyProofTampered/l=1/wrong_rPrime
=== RUN   TestSchemeVerifyProofTampered/l=1/wrong_resA
=== RUN   TestSchemeVerifyProofTampered/l=1/wrong_resT
=== RUN   TestSchemeVerifyProofTampered/l=1/wrong_resS
=== RUN   TestSchemeVerifyProofTampered/l=1/wrong_y-value
=== RUN   TestSchemeVerifyProofTampered/l=1/wrong_public_key
=== RUN   TestSchemeVerifyProofTampered/l=1/wrong_message
=== RUN   TestSchemeVerifyProofTampered/l=1/wrong_resCsk
=== RUN   TestSchemeVerifyProofTampered/l=1/wrong_disclosed_attribute
=== RUN   TestSchemeVerifyProofTampered/l=1/wrong_resCpk
=== RUN   TestSchemeVerifyProofTampered/l=2
=== RUN   TestSchemeVerifyProofTampered/l=2/wrong_rPrime
=== RUN   TestSchemeVerifyProofTampered/l=2/wrong_resA
=== RUN   TestSchemeVerifyProofTampered/l=2/wrong_resT
=== RUN   TestSchemeVerifyProofTampered/l=2/wrong_resS
=== RUN   TestSchemeVerifyProofTampered/l=2/wrong_y-value
=== RUN   TestSchemeVerifyProofTampered/l=2/wrong_resCpk
=== RUN   TestSchemeVerifyProofTampered/l=3
=== RUN   TestSchemeVerifyProofTampered/l=3/wrong_rPrime
=== RUN   TestSchemeVerifyProofTampered/l=3/wrong_resA
=== RUN   TestSchemeVerifyProofTampered/l=3/wrong_resT
=== RUN   TestSchemeVerifyProofTampered/l=3/wrong_resS
=== RUN   TestSchemeVerifyProofTampered/l=3/wrong_y-value
--- PASS: TestSchemeVerifyProofTampered (16.60s)
    --- PASS: TestSchemeVerifyProofTampered/l=1 (6.91s)
        --- PASS: TestSchemeVerifyProofTampered/l=1/wrong_rPrime (0.69s)
        --- PASS: TestSchemeVerifyProofTampered/l=1/wrong_resA (0.81s)
        --- PASS: TestSchemeVerifyProofTampered/l=1/wrong_resT (0.79s)
        --- PASS: TestSchemeVerifyProofTampered/l=1/wrong_resS (0.78s)
        --- PASS: TestSchemeVerifyProofTampered/l=1/wrong_y-value (0.77s)
        --- PASS: TestSchemeVerifyProofTampered/l=1/wrong_public_key (0.61s)
        --- PASS: TestSchemeVerifyProofTampered/l=1/wrong_message (0.66s)
        --- PASS: TestSchemeVerifyProofTampered/l=1/wrong_resCsk (0.65s)
        --- PASS: TestSchemeVerifyProofTampered/l=1/wrong_disclosed_attribute (0.60s)
        --- PASS: TestSchemeVerifyProofTampered/l=1/wrong_resCpk (0.55s)
    --- PASS: TestSchemeVerifyProofTampered/l=2 (5.44s)
        --- PASS: TestSchemeVerifyProofTampered/l=2/wrong_rPrime (0.75s)
        --- PASS: TestSchemeVerifyProofTampered/l=2/wrong_resA (0.89s)
        --- PASS: TestSchemeVerifyProofTampered/l=2/wrong_resT (1.07s)
        --- PASS: TestSchemeVerifyProofTampered/l=2/wrong_resS (0.94s)
        --- PASS: TestSchemeVerifyProofTampered/l=2/wrong_y-value (0.80s)
        --- PASS: TestSchemeVerifyProofTampered/l=2/wrong_resCpk (1.00s)
    --- PASS: TestSchemeVerifyProofTampered/l=3 (4.24s)
        --- PASS: TestSchemeVerifyProofTampered/l=3/wrong_rPrime (1.03s)
        --- PASS: TestSchemeVerifyProofTampered/l=3/wrong_resA (1.07s)
        --- PASS: TestSchemeVerifyProofTampered/l=3/wrong_resT (0.73s)
        --- PASS: TestSchemeVerifyProofTampered/l=3/wrong_resS (0.75s)
        --- PASS: TestSchemeVerifyProofTampered/l=3/wrong_y-value (0.67s)
=== RUN   TestSchemeProofMarshal
=== RUN   TestSchemeProofMarshal/toBytes_no_crash
=== RUN   TestSchemeProofMarshal/fromBytes_no_crash
=== RUN   TestSchemeProofMarshal/marshal_correct
--- PASS: TestSchemeProofMarshal (1.70s)
    --- PASS: TestSchemeProofMarshal/toBytes_no_crash (0.49s)
    --- PASS: TestSchemeProofMarshal/fromBytes_no_crash (0.65s)
    --- PASS: TestSchemeProofMarshal/marshal_correct (0.57s)
=== RUN   TestSchemeMarshalSizes
L     n     attributes      size

1     0     all disclosed   398 B
1     0     all hidden      398 B
1     0     one disclosed   398 B
1     1     all disclosed   469 B
1     1     all hidden      534 B
1     1     one disclosed   469 B
1     2     all disclosed   538 B
1     2     all hidden      670 B
1     2     one disclosed   603 B
1     3     all disclosed   609 B
1     3     all hidden      806 B
1     3     one disclosed   741 B
1     4     all disclosed   678 B
1     4     all hidden      942 B
1     4     one disclosed   875 B

2     0     all disclosed   801 B
2     0     all hidden      801 B
2     0     one disclosed   801 B
2     1     all disclosed   1.0 kB
2     1     all hidden      1.2 kB
2     1     one disclosed   1.1 kB
2     2     all disclosed   1.2 kB
2     2     all hidden      1.6 kB
2     2     one disclosed   1.5 kB
2     3     all disclosed   1.4 kB
2     3     all hidden      2.0 kB
2     3     one disclosed   1.9 kB
2     4     all disclosed   1.6 kB
2     4     all hidden      2.4 kB
2     4     one disclosed   2.3 kB

3     0     all disclosed   1.2 kB
3     0     all hidden      1.2 kB
3     0     one disclosed   1.2 kB
3     1     all disclosed   1.5 kB
3     1     all hidden      1.7 kB
3     1     one disclosed   1.7 kB
3     2     all disclosed   1.8 kB
3     2     all hidden      2.3 kB
3     2     one disclosed   2.2 kB
3     3     all disclosed   2.0 kB
3     3     all hidden      2.8 kB
3     3     one disclosed   2.7 kB
3     4     all disclosed   2.3 kB
3     4     all hidden      3.3 kB
3     4     one disclosed   3.3 kB

5     0     all disclosed   2.0 kB
5     0     all hidden      2.0 kB
5     0     one disclosed   2.0 kB
5     1     all disclosed   2.5 kB
5     1     all hidden      2.9 kB
5     1     one disclosed   2.9 kB
5     2     all disclosed   3.0 kB
5     2     all hidden      3.9 kB
5     2     one disclosed   3.8 kB
5     3     all disclosed   3.4 kB
5     3     all hidden      4.8 kB
5     3     one disclosed   4.7 kB
5     4     all disclosed   3.9 kB
5     4     all hidden      5.7 kB
5     4     one disclosed   5.7 kB

10    0     all disclosed   4.0 kB
10    0     all hidden      4.0 kB
10    0     one disclosed   4.0 kB
10    1     all disclosed   5.0 kB
10    1     all hidden      6.0 kB
10    1     one disclosed   5.9 kB
10    2     all disclosed   6.0 kB
10    2     all hidden      8.0 kB
10    2     one disclosed   7.9 kB
10    3     all disclosed   7.1 kB
10    3     all hidden      10 kB
10    3     one disclosed   9.9 kB
10    4     all disclosed   8.1 kB
10    4     all hidden      12 kB
10    4     one disclosed   12 kB
--- PASS: TestSchemeMarshalSizes (54.04s)
=== RUN   TestSchemeUserErrors
=== RUN   TestSchemeUserErrors/delegate
=== RUN   TestSchemeUserErrors/verify
=== RUN   TestSchemeUserErrors/prove_commitment_failure
=== RUN   TestSchemeUserErrors/prove
=== RUN   TestSchemeUserErrors/verify_proof_commitment_failure
=== RUN   TestSchemeUserErrors/verify_proof
--- PASS: TestSchemeUserErrors (2.41s)
    --- PASS: TestSchemeUserErrors/delegate (0.11s)
    --- PASS: TestSchemeUserErrors/verify (0.43s)
    --- PASS: TestSchemeUserErrors/prove_commitment_failure (0.43s)
    --- PASS: TestSchemeUserErrors/prove (0.22s)
    --- PASS: TestSchemeUserErrors/verify_proof_commitment_failure (0.65s)
    --- PASS: TestSchemeUserErrors/verify_proof (0.55s)
=== RUN   TestSchemeProofEquality
=== RUN   TestSchemeProofEquality/wrong_c
=== RUN   TestSchemeProofEquality/wrong_rPrime
=== RUN   TestSchemeProofEquality/wrong_resA
=== RUN   TestSchemeProofEquality/wrong_resT
=== RUN   TestSchemeProofEquality/wrong_resS
=== RUN   TestSchemeProofEquality/wrong_resCpk
=== RUN   TestSchemeProofEquality/wrong_resCsk
=== RUN   TestSchemeProofEquality/wrong_resNym
=== RUN   TestSchemeProofEquality/correct
--- PASS: TestSchemeProofEquality (8.18s)
    --- PASS: TestSchemeProofEquality/wrong_c (0.83s)
    --- PASS: TestSchemeProofEquality/wrong_rPrime (0.81s)
    --- PASS: TestSchemeProofEquality/wrong_resA (0.87s)
    --- PASS: TestSchemeProofEquality/wrong_resT (0.98s)
    --- PASS: TestSchemeProofEquality/wrong_resS (1.02s)
    --- PASS: TestSchemeProofEquality/wrong_resCpk (0.96s)
    --- PASS: TestSchemeProofEquality/wrong_resCsk (0.92s)
    --- PASS: TestSchemeProofEquality/wrong_resNym (0.91s)
    --- PASS: TestSchemeProofEquality/correct (0.90s)
=== RUN   TestSchemeCredentialsMarshal
--- PASS: TestSchemeCredentialsMarshal (0.20s)
=== RUN   TestSchemeCredentialsEquality
=== RUN   TestSchemeCredentialsEquality/correct
=== RUN   TestSchemeCredentialsEquality/wrong_public_key
=== RUN   TestSchemeCredentialsEquality/wrong_attribute
=== RUN   TestSchemeCredentialsEquality/wrong_signature
=== RUN   TestSchemeCredentialsEquality/wrong_number_of_signatures
--- PASS: TestSchemeCredentialsEquality (2.10s)
    --- PASS: TestSchemeCredentialsEquality/correct (0.41s)
    --- PASS: TestSchemeCredentialsEquality/wrong_public_key (0.41s)
    --- PASS: TestSchemeCredentialsEquality/wrong_attribute (0.44s)
    --- PASS: TestSchemeCredentialsEquality/wrong_signature (0.44s)
    --- PASS: TestSchemeCredentialsEquality/wrong_number_of_signatures (0.39s)
=== RUN   TestSchemeOptimizations
=== RUN   TestSchemeOptimizations/parallel=true_tate=true
=== RUN   TestSchemeOptimizations/parallel=true_tate=false
=== RUN   TestSchemeOptimizations/parallel=false_tate=true
=== RUN   TestSchemeOptimizations/parallel=false_tate=false
--- PASS: TestSchemeOptimizations (5.64s)
    --- PASS: TestSchemeOptimizations/parallel=true_tate=true (0.79s)
    --- PASS: TestSchemeOptimizations/parallel=true_tate=false (1.34s)
    --- PASS: TestSchemeOptimizations/parallel=false_tate=true (1.34s)
    --- PASS: TestSchemeOptimizations/parallel=false_tate=false (2.18s)
=== RUN   TestSchemeWorkersVary
=== RUN   TestSchemeWorkersVary/workers=0
=== RUN   TestSchemeWorkersVary/workers=1
=== RUN   TestSchemeWorkersVary/workers=2
=== RUN   TestSchemeWorkersVary/workers=3
=== RUN   TestSchemeWorkersVary/workers=4
=== RUN   TestSchemeWorkersVary/workers=5
=== RUN   TestSchemeWorkersVary/workers=6
=== RUN   TestSchemeWorkersVary/workers=7
=== RUN   TestSchemeWorkersVary/workers=8
=== RUN   TestSchemeWorkersVary/workers=9
=== RUN   TestSchemeWorkersVary/workers=10
=== RUN   TestSchemeWorkersVary/workers=11
=== RUN   TestSchemeWorkersVary/workers=12
=== RUN   TestSchemeWorkersVary/workers=13
=== RUN   TestSchemeWorkersVary/workers=14
--- PASS: TestSchemeWorkersVary (13.86s)
    --- PASS: TestSchemeWorkersVary/workers=0 (0.80s)
    --- PASS: TestSchemeWorkersVary/workers=1 (1.54s)
    --- PASS: TestSchemeWorkersVary/workers=2 (1.12s)
    --- PASS: TestSchemeWorkersVary/workers=3 (0.94s)
    --- PASS: TestSchemeWorkersVary/workers=4 (0.94s)
    --- PASS: TestSchemeWorkersVary/workers=5 (0.87s)
    --- PASS: TestSchemeWorkersVary/workers=6 (0.83s)
    --- PASS: TestSchemeWorkersVary/workers=7 (0.85s)
    --- PASS: TestSchemeWorkersVary/workers=8 (0.79s)
    --- PASS: TestSchemeWorkersVary/workers=9 (0.76s)
    --- PASS: TestSchemeWorkersVary/workers=10 (0.84s)
    --- PASS: TestSchemeWorkersVary/workers=11 (0.83s)
    --- PASS: TestSchemeWorkersVary/workers=12 (0.92s)
    --- PASS: TestSchemeWorkersVary/workers=13 (0.95s)
    --- PASS: TestSchemeWorkersVary/workers=14 (0.88s)
=== RUN   TestSchemeHInGTwo
=== RUN   TestSchemeHInGTwo/L=1
=== RUN   TestSchemeHInGTwo/L=2
=== RUN   TestSchemeHInGTwo/L=3
=== RUN   TestSchemeHInGTwo/L=5
=== RUN   TestSchemeHInGTwo/L=10
--- PASS: TestSchemeHInGTwo (9.30s)
    --- PASS: TestSchemeHInGTwo/L=1 (0.41s)
    --- PASS: TestSchemeHInGTwo/L=2 (0.78s)
    --- PASS: TestSchemeHInGTwo/L=3 (1.14s)
    --- PASS: TestSchemeHInGTwo/L=5 (1.92s)
    --- PASS: TestSchemeHInGTwo/L=10 (5.05s)
=== RUN   TestSchemeCredentialsUnMarshalingFail
--- PASS: TestSchemeCredentialsUnMarshalingFail (0.00s)
=== RUN   TestSchemeProofUnMarshalingFail
--- PASS: TestSchemeProofUnMarshalingFail (0.00s)
=== RUN   TestSchnorr
=== RUN   TestSchnorr/b=1
=== RUN   TestSchnorr/b=1/test_schnorr_deterministic_generate
=== RUN   TestSchnorr/b=1/test_schnorr_randomized_generate
=== RUN   TestSchnorr/b=1/test_schnorr_sign_no_crash
=== RUN   TestSchnorr/b=1/test_schnorr_verify_no_crash
=== RUN   TestSchnorr/b=1/test_schnorr_verify_correct
=== RUN   TestSchnorr/b=1/test_schnorr_verify_tampered_signature
=== RUN   TestSchnorr/b=1/test_schnorr_verify_wrong_message
=== RUN   TestSchnorr/b=1/test_schnorr_marshal
=== RUN   TestSchnorr/b=1/test_schnorr_un_marshal_fails
=== RUN   TestSchnorr/b=2
=== RUN   TestSchnorr/b=2/test_schnorr_deterministic_generate
=== RUN   TestSchnorr/b=2/test_schnorr_randomized_generate
=== RUN   TestSchnorr/b=2/test_schnorr_sign_no_crash
=== RUN   TestSchnorr/b=2/test_schnorr_verify_no_crash
=== RUN   TestSchnorr/b=2/test_schnorr_verify_correct
=== RUN   TestSchnorr/b=2/test_schnorr_verify_tampered_signature
=== RUN   TestSchnorr/b=2/test_schnorr_verify_wrong_message
=== RUN   TestSchnorr/b=2/test_schnorr_marshal
=== RUN   TestSchnorr/b=2/test_schnorr_un_marshal_fails
--- PASS: TestSchnorr (0.24s)
    --- PASS: TestSchnorr/b=1 (0.05s)
        --- PASS: TestSchnorr/b=1/test_schnorr_deterministic_generate (0.01s)
        --- PASS: TestSchnorr/b=1/test_schnorr_randomized_generate (0.00s)
        --- PASS: TestSchnorr/b=1/test_schnorr_sign_no_crash (0.01s)
        --- PASS: TestSchnorr/b=1/test_schnorr_verify_no_crash (0.01s)
        --- PASS: TestSchnorr/b=1/test_schnorr_verify_correct (0.01s)
        --- PASS: TestSchnorr/b=1/test_schnorr_verify_tampered_signature (0.01s)
        --- PASS: TestSchnorr/b=1/test_schnorr_verify_wrong_message (0.01s)
        --- PASS: TestSchnorr/b=1/test_schnorr_marshal (0.01s)
        --- PASS: TestSchnorr/b=1/test_schnorr_un_marshal_fails (0.00s)
    --- PASS: TestSchnorr/b=2 (0.19s)
        --- PASS: TestSchnorr/b=2/test_schnorr_deterministic_generate (0.01s)
        --- PASS: TestSchnorr/b=2/test_schnorr_randomized_generate (0.01s)
        --- PASS: TestSchnorr/b=2/test_schnorr_sign_no_crash (0.01s)
        --- PASS: TestSchnorr/b=2/test_schnorr_verify_no_crash (0.02s)
        --- PASS: TestSchnorr/b=2/test_schnorr_verify_correct (0.03s)
        --- PASS: TestSchnorr/b=2/test_schnorr_verify_tampered_signature (0.04s)
        --- PASS: TestSchnorr/b=2/test_schnorr_verify_wrong_message (0.02s)
        --- PASS: TestSchnorr/b=2/test_schnorr_marshal (0.03s)
        --- PASS: TestSchnorr/b=2/test_schnorr_un_marshal_fails (0.00s)
=== RUN   TestSiblings
=== RUN   TestSiblings/b=1
=== RUN   TestSiblings/b=1/test_siblings_schnorr
=== RUN   TestSiblings/b=1/test_siblings_groth
=== RUN   TestSiblings/b=2
=== RUN   TestSiblings/b=2/test_siblings_schnorr
=== RUN   TestSiblings/b=2/test_siblings_groth
--- PASS: TestSiblings (0.56s)
    --- PASS: TestSiblings/b=1 (0.24s)
        --- PASS: TestSiblings/b=1/test_siblings_schnorr (0.03s)
        --- PASS: TestSiblings/b=1/test_siblings_groth (0.21s)
    --- PASS: TestSiblings/b=2 (0.26s)
        --- PASS: TestSiblings/b=2/test_siblings_schnorr (0.01s)
        --- PASS: TestSiblings/b=2/test_siblings_groth (0.25s)
=== RUN   TestAMCLAssumptions
=== RUN   TestAMCLAssumptions/SEED=0
=== RUN   TestAMCLAssumptions/SEED=0/exponent_in_or_out_fexp
=== RUN   TestAMCLAssumptions/SEED=0/tate_times_tate_is_tate2
=== RUN   TestAMCLAssumptions/SEED=0/regular_pairings
=== RUN   TestAMCLAssumptions/SEED=0/tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=0/tate2_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=0/tate2_plus_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=0/3_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=0/fexp_homomorphism
=== RUN   TestAMCLAssumptions/SEED=0/power_operation_for_fp12_
=== RUN   TestAMCLAssumptions/SEED=0/exponentiation_distributivity
=== RUN   TestAMCLAssumptions/SEED=0/wrong_inverse
=== RUN   TestAMCLAssumptions/SEED=0/right_inverse
=== RUN   TestAMCLAssumptions/SEED=0/group_element_inverse_vs_neg
=== RUN   TestAMCLAssumptions/SEED=0/invert_by_raising_to_-1
=== RUN   TestAMCLAssumptions/SEED=0/invert_argument_vs_invert_result
=== RUN   TestAMCLAssumptions/SEED=1
=== RUN   TestAMCLAssumptions/SEED=1/exponent_in_or_out_fexp
=== RUN   TestAMCLAssumptions/SEED=1/tate_times_tate_is_tate2
=== RUN   TestAMCLAssumptions/SEED=1/regular_pairings
=== RUN   TestAMCLAssumptions/SEED=1/tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=1/tate2_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=1/tate2_plus_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=1/3_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=1/fexp_homomorphism
=== RUN   TestAMCLAssumptions/SEED=1/power_operation_for_fp12_
=== RUN   TestAMCLAssumptions/SEED=1/exponentiation_distributivity
=== RUN   TestAMCLAssumptions/SEED=1/wrong_inverse
=== RUN   TestAMCLAssumptions/SEED=1/right_inverse
=== RUN   TestAMCLAssumptions/SEED=1/group_element_inverse_vs_neg
=== RUN   TestAMCLAssumptions/SEED=1/invert_by_raising_to_-1
=== RUN   TestAMCLAssumptions/SEED=1/invert_argument_vs_invert_result
=== RUN   TestAMCLAssumptions/SEED=2
=== RUN   TestAMCLAssumptions/SEED=2/exponent_in_or_out_fexp
=== RUN   TestAMCLAssumptions/SEED=2/tate_times_tate_is_tate2
=== RUN   TestAMCLAssumptions/SEED=2/regular_pairings
=== RUN   TestAMCLAssumptions/SEED=2/tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=2/tate2_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=2/tate2_plus_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=2/3_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=2/fexp_homomorphism
=== RUN   TestAMCLAssumptions/SEED=2/power_operation_for_fp12_
=== RUN   TestAMCLAssumptions/SEED=2/exponentiation_distributivity
=== RUN   TestAMCLAssumptions/SEED=2/wrong_inverse
=== RUN   TestAMCLAssumptions/SEED=2/right_inverse
=== RUN   TestAMCLAssumptions/SEED=2/group_element_inverse_vs_neg
=== RUN   TestAMCLAssumptions/SEED=2/invert_by_raising_to_-1
=== RUN   TestAMCLAssumptions/SEED=2/invert_argument_vs_invert_result
=== RUN   TestAMCLAssumptions/SEED=3
=== RUN   TestAMCLAssumptions/SEED=3/exponent_in_or_out_fexp
=== RUN   TestAMCLAssumptions/SEED=3/tate_times_tate_is_tate2
=== RUN   TestAMCLAssumptions/SEED=3/regular_pairings
=== RUN   TestAMCLAssumptions/SEED=3/tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=3/tate2_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=3/tate2_plus_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=3/3_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=3/fexp_homomorphism
=== RUN   TestAMCLAssumptions/SEED=3/power_operation_for_fp12_
=== RUN   TestAMCLAssumptions/SEED=3/exponentiation_distributivity
=== RUN   TestAMCLAssumptions/SEED=3/wrong_inverse
=== RUN   TestAMCLAssumptions/SEED=3/right_inverse
=== RUN   TestAMCLAssumptions/SEED=3/group_element_inverse_vs_neg
=== RUN   TestAMCLAssumptions/SEED=3/invert_by_raising_to_-1
=== RUN   TestAMCLAssumptions/SEED=3/invert_argument_vs_invert_result
=== RUN   TestAMCLAssumptions/SEED=4
=== RUN   TestAMCLAssumptions/SEED=4/exponent_in_or_out_fexp
=== RUN   TestAMCLAssumptions/SEED=4/tate_times_tate_is_tate2
=== RUN   TestAMCLAssumptions/SEED=4/regular_pairings
=== RUN   TestAMCLAssumptions/SEED=4/tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=4/tate2_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=4/tate2_plus_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=4/3_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=4/fexp_homomorphism
=== RUN   TestAMCLAssumptions/SEED=4/power_operation_for_fp12_
=== RUN   TestAMCLAssumptions/SEED=4/exponentiation_distributivity
=== RUN   TestAMCLAssumptions/SEED=4/wrong_inverse
=== RUN   TestAMCLAssumptions/SEED=4/right_inverse
=== RUN   TestAMCLAssumptions/SEED=4/group_element_inverse_vs_neg
=== RUN   TestAMCLAssumptions/SEED=4/invert_by_raising_to_-1
=== RUN   TestAMCLAssumptions/SEED=4/invert_argument_vs_invert_result
=== RUN   TestAMCLAssumptions/SEED=5
=== RUN   TestAMCLAssumptions/SEED=5/exponent_in_or_out_fexp
=== RUN   TestAMCLAssumptions/SEED=5/tate_times_tate_is_tate2
=== RUN   TestAMCLAssumptions/SEED=5/regular_pairings
=== RUN   TestAMCLAssumptions/SEED=5/tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=5/tate2_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=5/tate2_plus_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=5/3_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=5/fexp_homomorphism
=== RUN   TestAMCLAssumptions/SEED=5/power_operation_for_fp12_
=== RUN   TestAMCLAssumptions/SEED=5/exponentiation_distributivity
=== RUN   TestAMCLAssumptions/SEED=5/wrong_inverse
=== RUN   TestAMCLAssumptions/SEED=5/right_inverse
=== RUN   TestAMCLAssumptions/SEED=5/group_element_inverse_vs_neg
=== RUN   TestAMCLAssumptions/SEED=5/invert_by_raising_to_-1
=== RUN   TestAMCLAssumptions/SEED=5/invert_argument_vs_invert_result
=== RUN   TestAMCLAssumptions/SEED=6
=== RUN   TestAMCLAssumptions/SEED=6/exponent_in_or_out_fexp
=== RUN   TestAMCLAssumptions/SEED=6/tate_times_tate_is_tate2
=== RUN   TestAMCLAssumptions/SEED=6/regular_pairings
=== RUN   TestAMCLAssumptions/SEED=6/tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=6/tate2_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=6/tate2_plus_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=6/3_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=6/fexp_homomorphism
=== RUN   TestAMCLAssumptions/SEED=6/power_operation_for_fp12_
=== RUN   TestAMCLAssumptions/SEED=6/exponentiation_distributivity
=== RUN   TestAMCLAssumptions/SEED=6/wrong_inverse
=== RUN   TestAMCLAssumptions/SEED=6/right_inverse
=== RUN   TestAMCLAssumptions/SEED=6/group_element_inverse_vs_neg
=== RUN   TestAMCLAssumptions/SEED=6/invert_by_raising_to_-1
=== RUN   TestAMCLAssumptions/SEED=6/invert_argument_vs_invert_result
=== RUN   TestAMCLAssumptions/SEED=7
=== RUN   TestAMCLAssumptions/SEED=7/exponent_in_or_out_fexp
=== RUN   TestAMCLAssumptions/SEED=7/tate_times_tate_is_tate2
=== RUN   TestAMCLAssumptions/SEED=7/regular_pairings
=== RUN   TestAMCLAssumptions/SEED=7/tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=7/tate2_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=7/tate2_plus_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=7/3_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=7/fexp_homomorphism
=== RUN   TestAMCLAssumptions/SEED=7/power_operation_for_fp12_
=== RUN   TestAMCLAssumptions/SEED=7/exponentiation_distributivity
=== RUN   TestAMCLAssumptions/SEED=7/wrong_inverse
=== RUN   TestAMCLAssumptions/SEED=7/right_inverse
=== RUN   TestAMCLAssumptions/SEED=7/group_element_inverse_vs_neg
=== RUN   TestAMCLAssumptions/SEED=7/invert_by_raising_to_-1
=== RUN   TestAMCLAssumptions/SEED=7/invert_argument_vs_invert_result
=== RUN   TestAMCLAssumptions/SEED=8
=== RUN   TestAMCLAssumptions/SEED=8/exponent_in_or_out_fexp
=== RUN   TestAMCLAssumptions/SEED=8/tate_times_tate_is_tate2
=== RUN   TestAMCLAssumptions/SEED=8/regular_pairings
=== RUN   TestAMCLAssumptions/SEED=8/tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=8/tate2_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=8/tate2_plus_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=8/3_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=8/fexp_homomorphism
=== RUN   TestAMCLAssumptions/SEED=8/power_operation_for_fp12_
=== RUN   TestAMCLAssumptions/SEED=8/exponentiation_distributivity
=== RUN   TestAMCLAssumptions/SEED=8/wrong_inverse
=== RUN   TestAMCLAssumptions/SEED=8/right_inverse
=== RUN   TestAMCLAssumptions/SEED=8/group_element_inverse_vs_neg
=== RUN   TestAMCLAssumptions/SEED=8/invert_by_raising_to_-1
=== RUN   TestAMCLAssumptions/SEED=8/invert_argument_vs_invert_result
=== RUN   TestAMCLAssumptions/SEED=9
=== RUN   TestAMCLAssumptions/SEED=9/exponent_in_or_out_fexp
=== RUN   TestAMCLAssumptions/SEED=9/tate_times_tate_is_tate2
=== RUN   TestAMCLAssumptions/SEED=9/regular_pairings
=== RUN   TestAMCLAssumptions/SEED=9/tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=9/tate2_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=9/tate2_plus_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=9/3_tate_plus_fexp_pairings
=== RUN   TestAMCLAssumptions/SEED=9/fexp_homomorphism
=== RUN   TestAMCLAssumptions/SEED=9/power_operation_for_fp12_
=== RUN   TestAMCLAssumptions/SEED=9/exponentiation_distributivity
=== RUN   TestAMCLAssumptions/SEED=9/wrong_inverse
=== RUN   TestAMCLAssumptions/SEED=9/right_inverse
=== RUN   TestAMCLAssumptions/SEED=9/group_element_inverse_vs_neg
=== RUN   TestAMCLAssumptions/SEED=9/invert_by_raising_to_-1
=== RUN   TestAMCLAssumptions/SEED=9/invert_argument_vs_invert_result
--- PASS: TestAMCLAssumptions (11.83s)
    --- PASS: TestAMCLAssumptions/SEED=0 (1.19s)
        --- PASS: TestAMCLAssumptions/SEED=0/exponent_in_or_out_fexp (0.08s)
        --- PASS: TestAMCLAssumptions/SEED=0/tate_times_tate_is_tate2 (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=0/regular_pairings (0.15s)
        --- PASS: TestAMCLAssumptions/SEED=0/tate_plus_fexp_pairings (0.13s)
        --- PASS: TestAMCLAssumptions/SEED=0/tate2_plus_fexp_pairings (0.12s)
        --- PASS: TestAMCLAssumptions/SEED=0/tate2_plus_tate_plus_fexp_pairings (0.16s)
        --- PASS: TestAMCLAssumptions/SEED=0/3_tate_plus_fexp_pairings (0.18s)
        --- PASS: TestAMCLAssumptions/SEED=0/fexp_homomorphism (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=0/power_operation_for_fp12_ (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=0/exponentiation_distributivity (0.01s)
        --- PASS: TestAMCLAssumptions/SEED=0/wrong_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=0/right_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=0/group_element_inverse_vs_neg (0.00s)
        --- PASS: TestAMCLAssumptions/SEED=0/invert_by_raising_to_-1 (0.04s)
        --- PASS: TestAMCLAssumptions/SEED=0/invert_argument_vs_invert_result (0.05s)
    --- PASS: TestAMCLAssumptions/SEED=1 (1.35s)
        --- PASS: TestAMCLAssumptions/SEED=1/exponent_in_or_out_fexp (0.08s)
        --- PASS: TestAMCLAssumptions/SEED=1/tate_times_tate_is_tate2 (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=1/regular_pairings (0.15s)
        --- PASS: TestAMCLAssumptions/SEED=1/tate_plus_fexp_pairings (0.13s)
        --- PASS: TestAMCLAssumptions/SEED=1/tate2_plus_fexp_pairings (0.13s)
        --- PASS: TestAMCLAssumptions/SEED=1/tate2_plus_tate_plus_fexp_pairings (0.17s)
        --- PASS: TestAMCLAssumptions/SEED=1/3_tate_plus_fexp_pairings (0.25s)
        --- PASS: TestAMCLAssumptions/SEED=1/fexp_homomorphism (0.07s)
        --- PASS: TestAMCLAssumptions/SEED=1/power_operation_for_fp12_ (0.04s)
        --- PASS: TestAMCLAssumptions/SEED=1/exponentiation_distributivity (0.01s)
        --- PASS: TestAMCLAssumptions/SEED=1/wrong_inverse (0.08s)
        --- PASS: TestAMCLAssumptions/SEED=1/right_inverse (0.07s)
        --- PASS: TestAMCLAssumptions/SEED=1/group_element_inverse_vs_neg (0.00s)
        --- PASS: TestAMCLAssumptions/SEED=1/invert_by_raising_to_-1 (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=1/invert_argument_vs_invert_result (0.06s)
    --- PASS: TestAMCLAssumptions/SEED=2 (1.16s)
        --- PASS: TestAMCLAssumptions/SEED=2/exponent_in_or_out_fexp (0.08s)
        --- PASS: TestAMCLAssumptions/SEED=2/tate_times_tate_is_tate2 (0.07s)
        --- PASS: TestAMCLAssumptions/SEED=2/regular_pairings (0.15s)
        --- PASS: TestAMCLAssumptions/SEED=2/tate_plus_fexp_pairings (0.13s)
        --- PASS: TestAMCLAssumptions/SEED=2/tate2_plus_fexp_pairings (0.12s)
        --- PASS: TestAMCLAssumptions/SEED=2/tate2_plus_tate_plus_fexp_pairings (0.16s)
        --- PASS: TestAMCLAssumptions/SEED=2/3_tate_plus_fexp_pairings (0.16s)
        --- PASS: TestAMCLAssumptions/SEED=2/fexp_homomorphism (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=2/power_operation_for_fp12_ (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=2/exponentiation_distributivity (0.01s)
        --- PASS: TestAMCLAssumptions/SEED=2/wrong_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=2/right_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=2/group_element_inverse_vs_neg (0.00s)
        --- PASS: TestAMCLAssumptions/SEED=2/invert_by_raising_to_-1 (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=2/invert_argument_vs_invert_result (0.05s)
    --- PASS: TestAMCLAssumptions/SEED=3 (1.11s)
        --- PASS: TestAMCLAssumptions/SEED=3/exponent_in_or_out_fexp (0.07s)
        --- PASS: TestAMCLAssumptions/SEED=3/tate_times_tate_is_tate2 (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=3/regular_pairings (0.14s)
        --- PASS: TestAMCLAssumptions/SEED=3/tate_plus_fexp_pairings (0.12s)
        --- PASS: TestAMCLAssumptions/SEED=3/tate2_plus_fexp_pairings (0.11s)
        --- PASS: TestAMCLAssumptions/SEED=3/tate2_plus_tate_plus_fexp_pairings (0.15s)
        --- PASS: TestAMCLAssumptions/SEED=3/3_tate_plus_fexp_pairings (0.17s)
        --- PASS: TestAMCLAssumptions/SEED=3/fexp_homomorphism (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=3/power_operation_for_fp12_ (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=3/exponentiation_distributivity (0.01s)
        --- PASS: TestAMCLAssumptions/SEED=3/wrong_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=3/right_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=3/group_element_inverse_vs_neg (0.00s)
        --- PASS: TestAMCLAssumptions/SEED=3/invert_by_raising_to_-1 (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=3/invert_argument_vs_invert_result (0.04s)
    --- PASS: TestAMCLAssumptions/SEED=4 (1.15s)
        --- PASS: TestAMCLAssumptions/SEED=4/exponent_in_or_out_fexp (0.07s)
        --- PASS: TestAMCLAssumptions/SEED=4/tate_times_tate_is_tate2 (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=4/regular_pairings (0.13s)
        --- PASS: TestAMCLAssumptions/SEED=4/tate_plus_fexp_pairings (0.12s)
        --- PASS: TestAMCLAssumptions/SEED=4/tate2_plus_fexp_pairings (0.11s)
        --- PASS: TestAMCLAssumptions/SEED=4/tate2_plus_tate_plus_fexp_pairings (0.16s)
        --- PASS: TestAMCLAssumptions/SEED=4/3_tate_plus_fexp_pairings (0.18s)
        --- PASS: TestAMCLAssumptions/SEED=4/fexp_homomorphism (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=4/power_operation_for_fp12_ (0.04s)
        --- PASS: TestAMCLAssumptions/SEED=4/exponentiation_distributivity (0.01s)
        --- PASS: TestAMCLAssumptions/SEED=4/wrong_inverse (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=4/right_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=4/group_element_inverse_vs_neg (0.00s)
        --- PASS: TestAMCLAssumptions/SEED=4/invert_by_raising_to_-1 (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=4/invert_argument_vs_invert_result (0.05s)
    --- PASS: TestAMCLAssumptions/SEED=5 (1.18s)
        --- PASS: TestAMCLAssumptions/SEED=5/exponent_in_or_out_fexp (0.07s)
        --- PASS: TestAMCLAssumptions/SEED=5/tate_times_tate_is_tate2 (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=5/regular_pairings (0.17s)
        --- PASS: TestAMCLAssumptions/SEED=5/tate_plus_fexp_pairings (0.12s)
        --- PASS: TestAMCLAssumptions/SEED=5/tate2_plus_fexp_pairings (0.11s)
        --- PASS: TestAMCLAssumptions/SEED=5/tate2_plus_tate_plus_fexp_pairings (0.18s)
        --- PASS: TestAMCLAssumptions/SEED=5/3_tate_plus_fexp_pairings (0.17s)
        --- PASS: TestAMCLAssumptions/SEED=5/fexp_homomorphism (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=5/power_operation_for_fp12_ (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=5/exponentiation_distributivity (0.01s)
        --- PASS: TestAMCLAssumptions/SEED=5/wrong_inverse (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=5/right_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=5/group_element_inverse_vs_neg (0.00s)
        --- PASS: TestAMCLAssumptions/SEED=5/invert_by_raising_to_-1 (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=5/invert_argument_vs_invert_result (0.05s)
    --- PASS: TestAMCLAssumptions/SEED=6 (1.13s)
        --- PASS: TestAMCLAssumptions/SEED=6/exponent_in_or_out_fexp (0.07s)
        --- PASS: TestAMCLAssumptions/SEED=6/tate_times_tate_is_tate2 (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=6/regular_pairings (0.14s)
        --- PASS: TestAMCLAssumptions/SEED=6/tate_plus_fexp_pairings (0.12s)
        --- PASS: TestAMCLAssumptions/SEED=6/tate2_plus_fexp_pairings (0.13s)
        --- PASS: TestAMCLAssumptions/SEED=6/tate2_plus_tate_plus_fexp_pairings (0.16s)
        --- PASS: TestAMCLAssumptions/SEED=6/3_tate_plus_fexp_pairings (0.16s)
        --- PASS: TestAMCLAssumptions/SEED=6/fexp_homomorphism (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=6/power_operation_for_fp12_ (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=6/exponentiation_distributivity (0.01s)
        --- PASS: TestAMCLAssumptions/SEED=6/wrong_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=6/right_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=6/group_element_inverse_vs_neg (0.00s)
        --- PASS: TestAMCLAssumptions/SEED=6/invert_by_raising_to_-1 (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=6/invert_argument_vs_invert_result (0.05s)
    --- PASS: TestAMCLAssumptions/SEED=7 (1.28s)
        --- PASS: TestAMCLAssumptions/SEED=7/exponent_in_or_out_fexp (0.07s)
        --- PASS: TestAMCLAssumptions/SEED=7/tate_times_tate_is_tate2 (0.08s)
        --- PASS: TestAMCLAssumptions/SEED=7/regular_pairings (0.15s)
        --- PASS: TestAMCLAssumptions/SEED=7/tate_plus_fexp_pairings (0.15s)
        --- PASS: TestAMCLAssumptions/SEED=7/tate2_plus_fexp_pairings (0.13s)
        --- PASS: TestAMCLAssumptions/SEED=7/tate2_plus_tate_plus_fexp_pairings (0.16s)
        --- PASS: TestAMCLAssumptions/SEED=7/3_tate_plus_fexp_pairings (0.18s)
        --- PASS: TestAMCLAssumptions/SEED=7/fexp_homomorphism (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=7/power_operation_for_fp12_ (0.04s)
        --- PASS: TestAMCLAssumptions/SEED=7/exponentiation_distributivity (0.01s)
        --- PASS: TestAMCLAssumptions/SEED=7/wrong_inverse (0.08s)
        --- PASS: TestAMCLAssumptions/SEED=7/right_inverse (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=7/group_element_inverse_vs_neg (0.00s)
        --- PASS: TestAMCLAssumptions/SEED=7/invert_by_raising_to_-1 (0.04s)
        --- PASS: TestAMCLAssumptions/SEED=7/invert_argument_vs_invert_result (0.05s)
    --- PASS: TestAMCLAssumptions/SEED=8 (1.09s)
        --- PASS: TestAMCLAssumptions/SEED=8/exponent_in_or_out_fexp (0.07s)
        --- PASS: TestAMCLAssumptions/SEED=8/tate_times_tate_is_tate2 (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=8/regular_pairings (0.15s)
        --- PASS: TestAMCLAssumptions/SEED=8/tate_plus_fexp_pairings (0.12s)
        --- PASS: TestAMCLAssumptions/SEED=8/tate2_plus_fexp_pairings (0.12s)
        --- PASS: TestAMCLAssumptions/SEED=8/tate2_plus_tate_plus_fexp_pairings (0.15s)
        --- PASS: TestAMCLAssumptions/SEED=8/3_tate_plus_fexp_pairings (0.15s)
        --- PASS: TestAMCLAssumptions/SEED=8/fexp_homomorphism (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=8/power_operation_for_fp12_ (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=8/exponentiation_distributivity (0.01s)
        --- PASS: TestAMCLAssumptions/SEED=8/wrong_inverse (0.04s)
        --- PASS: TestAMCLAssumptions/SEED=8/right_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=8/group_element_inverse_vs_neg (0.00s)
        --- PASS: TestAMCLAssumptions/SEED=8/invert_by_raising_to_-1 (0.03s)
        --- PASS: TestAMCLAssumptions/SEED=8/invert_argument_vs_invert_result (0.04s)
    --- PASS: TestAMCLAssumptions/SEED=9 (1.18s)
        --- PASS: TestAMCLAssumptions/SEED=9/exponent_in_or_out_fexp (0.08s)
        --- PASS: TestAMCLAssumptions/SEED=9/tate_times_tate_is_tate2 (0.06s)
        --- PASS: TestAMCLAssumptions/SEED=9/regular_pairings (0.16s)
        --- PASS: TestAMCLAssumptions/SEED=9/tate_plus_fexp_pairings (0.13s)
        --- PASS: TestAMCLAssumptions/SEED=9/tate2_plus_fexp_pairings (0.12s)
        --- PASS: TestAMCLAssumptions/SEED=9/tate2_plus_tate_plus_fexp_pairings (0.17s)
        --- PASS: TestAMCLAssumptions/SEED=9/3_tate_plus_fexp_pairings (0.17s)
        --- PASS: TestAMCLAssumptions/SEED=9/fexp_homomorphism (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=9/power_operation_for_fp12_ (0.04s)
        --- PASS: TestAMCLAssumptions/SEED=9/exponentiation_distributivity (0.00s)
        --- PASS: TestAMCLAssumptions/SEED=9/wrong_inverse (0.04s)
        --- PASS: TestAMCLAssumptions/SEED=9/right_inverse (0.05s)
        --- PASS: TestAMCLAssumptions/SEED=9/group_element_inverse_vs_neg (0.00s)
        --- PASS: TestAMCLAssumptions/SEED=9/invert_by_raising_to_-1 (0.04s)
        --- PASS: TestAMCLAssumptions/SEED=9/invert_argument_vs_invert_result (0.04s)
=== RUN   TestElementaryProofs
=== RUN   TestElementaryProofs/first_commitment_for_i=1
=== RUN   TestElementaryProofs/second_commitment_for_i=1
--- PASS: TestElementaryProofs (0.42s)
    --- PASS: TestElementaryProofs/first_commitment_for_i=1 (0.17s)
    --- PASS: TestElementaryProofs/second_commitment_for_i=1 (0.24s)
=== RUN   TestMiscellaneous
=== RUN   TestMiscellaneous/point_list_equal
=== RUN   TestMiscellaneous/bigMinusMod
=== RUN   TestMiscellaneous/PointFromBytes
=== RUN   TestMiscellaneous/subtraction_and_addition
=== RUN   TestMiscellaneous/subtraction_and_addition/first=true
=== RUN   TestMiscellaneous/subtraction_and_addition/first=false
--- PASS: TestMiscellaneous (0.00s)
    --- PASS: TestMiscellaneous/point_list_equal (0.00s)
    --- PASS: TestMiscellaneous/bigMinusMod (0.00s)
    --- PASS: TestMiscellaneous/PointFromBytes (0.00s)
    --- PASS: TestMiscellaneous/subtraction_and_addition (0.00s)
        --- PASS: TestMiscellaneous/subtraction_and_addition/first=true (0.00s)
        --- PASS: TestMiscellaneous/subtraction_and_addition/first=false (0.00s)
=== RUN   TestPrintObjectsDeclarations
--- PASS: TestPrintObjectsDeclarations (0.60s)
PASS
ok  	github.com/dbogatov/dac-lib/dac	151.707s
```

</details>
