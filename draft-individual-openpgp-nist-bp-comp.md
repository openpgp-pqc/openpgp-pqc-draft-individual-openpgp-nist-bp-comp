---
title: "PQ/T Composite Schemes for OpenPGP using NIST and Brainpool Domain Parameters"
abbrev: "NIST Brainpool PQC"
category: info

docname: draft-individual-openpgp-nist-bp-comp-latest
submissiontype: IETF
v: 3
area: sec
workgroup: Network Working Group
keyword: Internet-Draft
venue:
  group: WG
  type: Working Group
  mail: openpgp@ietf.org
  arch: "https://mailarchive.ietf.org/arch/browse/openpgp/"
  repo: "https://github.com/openpgp-pqc/draft-individual-openpgp-nist-bp-comp"

author:
 -
    ins: Q. Dang
    name: Quynh Dang
    org: NIST
    country: USA
    email: quynh.dang@nist.gov
 -
    ins: J. Roth
    name: Johannes Roth
    org: MTG AG
    country: Germany
    email: johannes.roth@mtg.de
 -
    ins: F. Strenzke
    name: Falko Strenzke
    org: MTG AG
    country: Germany
    email: falko.strenzke@mtg.de

normative:

  RFC7748:

  RFC8032:

  RFC3394:

  RFC8126:

  I-D.ietf-openpgp-crypto-refresh:

informative:

  RFC5639:

  NIST-PQC:
    target: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization
    title: Post-Quantum Cryptography Standardization
    author:
      -
        ins: L. Chen
        name: Lily Chen
      -
        ins: D. Moody
        name: Dustin Moody
      -
        ins: Y. Liu
        name: Yi-Kai Liu
    date: December 2016

  NISTIR-8413:
    target: https://doi.org/10.6028/NIST.IR.8413-upd1
    title: Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process
    author:
      -
        ins: G. Alagic
        name: Gorjan Alagic
      -
        ins: D. Apon
        name: Daniel Apon
      -
        ins: D. Cooper
        name: David Cooper
      -
        ins: Q. Dang
        name: Quynh Dang
      -
        ins: T. Dang
        name: Thinh Dang
      -
        ins: J. Kelsey
        name: John Kelsay
      -
        ins: J. Lichtinger
        name: Jacob Lichtinger
      -
        ins: C. Miller
        name: Carl Miller
      -
        ins: D. Moody
        name: Dustin Moody
      -
        ins: R. Peralta
        name: Rene Peralta
      -
        ins: R. Perlner
        name: Ray Perlner
      -
        ins: A. Robinson
        name: Angela Robinson
      -
        ins: D. Smith-Tone
        name: Daniel Smith-Tone
      -
        ins: Y. Liu
        name: Yi-Kai Liu
    date: September 2022
    seriesinfo:
      NIST IR 8413

  SP800-56C:
    target: https://doi.org/10.6028/NIST.SP.800-56Cr2
    title: Recommendation for Key-Derivation Methods in Key-Establishment Schemes
    author:
      -
        ins: E. Barker
        name: Elaine Barker
      -
        ins: L. Chen
        name: Lily Chen
      -
        ins: R. Davis
        name: Richard Davis
    date: August 2020
    seriesinfo:
      NIST Special Publication 800-56C Rev. 2

  SP800-185:
    target: https://doi.org/10.6028/NIST.SP.800-185
    title: 'SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash'
    author:
      -
        ins: J. Kelsey
        name: John Kelsey
      -
        ins: S. Chang
        name: Shu-jen Chang
      -
        ins: R. Perlner
        name: Ray Perlner
    date: December 2016
    seriesinfo:
      NIST Special Publication 800-185

  SP800-56A:
    target: https://doi.org/10.6028/NIST.SP.800-56Ar3
    title: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography
    author:
      -
        ins: E. Barker
        name: Elaine Barker
      -
        ins: L. Chen
        name: Lily Chen
      -
        ins: A. Roginsky
        name: Allen Roginsky
      -
        ins: A. Vassilev
        name: Apostol Vassilev
      -
        ins: R. Davis
        name: Richard Davis
    date: April 2018
    seriesinfo:
      NIST Special Publication 800-56A Rev. 3

  SP800-186:
    target: https://doi.org/10.6028/NIST.SP.800-186
    title: 'Recommendations for Discrete Logarithm-Based Cryptography:  Elliptic Curve Domain Parameters'
    author:
      -
        ins: L. Chen
        name: Lily Chen
      -
        ins: D. Moody
        name: Dustin Moody
      -
        ins: A. Regenscheid
        name: Andrew Regenscheid
      -
        ins: K. Randall
        name: Karen Randall
    date: February 2023
    seriesinfo:
      NIST Special Publication 800-186

  SEC1:
    target: https://secg.org/sec1-v2.pdf
    title: "Standards for Efficient Cryptography 1 (SEC 1)"
    author:
      - org: Standards for Efficient Cryptography Group
    date: May 2009

  FIPS-203:
      target: https://doi.org/10.6028/NIST.FIPS.203.ipd
      title: Module-Lattice-Based Key-Encapsulation Mechanism Standard
      author:
        - org: National Institute of Standards and Technology
      date: August 2023

  FIPS-204:
      target: https://doi.org/10.6028/NIST.FIPS.204.ipd
      title: Module-Lattice-Based Digital Signature Standard
      author:
        - org: National Institute of Standards and Technology
      date: August 2023

  FIPS-205:
      target: https://doi.org/10.6028/NIST.FIPS.205.ipd
      title: Stateless Hash-Based Digital Signature Standard
      author:
        - org: National Institute of Standards and Technology
      date: August 2023

  draft-driscoll-pqt-hybrid-terminology:
    target: https://datatracker.ietf.org/doc/html/draft-driscoll-pqt-hybrid-terminology
    title: Terminology for Post-Quantum Traditional Hybrid Schemes
    author:
      -
        ins: F. Driscoll
        name: Florence Driscoll
    date: March 2023

  GHP18:
    target: https://doi.org/10.1007/978-3-319-76578-5_7
    title: KEM Combiners
    date: 2018
    author:
      -
        ins: F. Giacon
        name: Federico Giacon
      -
        ins: F. Heuer
        name: Felix Heuer
      -
        ins: B. Poettering
        name: Bertram Poettering

  BDPA08:
    target: https://doi.org/10.1007/978-3-540-78967-3_11
    title: On the Indifferentiability of the Sponge Construction
    author:
      -
        ins: G. Bertoni
        name: Guido Bertoni
      -
        ins: J. Daemen
        name: Joan Daemen
      -
        ins: M. Peters
        name: Michael Peters
      -
        ins: G. Assche
        name: Gilles van Assche
    date: 2008

  CS03:
    target: https://doi.org/10.1137/S0097539702403773
    title: Design and Analysis of Practical Public-Key Encryption Schemes Secure against Adaptive Chosen Ciphertext Attack
    author:
      -
        ins: R. Cramer
        name: Ronald Cramer
      -
        ins: V. Shoup
        name: Victor Shoup
    date: 2003

--- abstract

This document defines PQ/T composite schemes based on ML-KEM and ML-DSA combined with ECC algorithms for the OpenPGP protocol.
TODO
--- middle

# Introduction


## Conventions used in this Document

### Terminology for Multi-Algorithm Schemes

The terminology in this document is oriented towards the definitions in [draft-driscoll-pqt-hybrid-terminology].
Specifically, the terms "multi-algorithm", "composite" and "non-composite" are used in correspondence with the definitions therein.
The abbreviation "PQ" is used for post-quantum schemes.
To denote the combination of post-quantum and traditional schemes, the abbreviation "PQ/T" is used.
The short form "PQ(/T)" stands for PQ or PQ/T.

## Post-Quantum Cryptography

This section describes the individual post-quantum cryptographic schemes.
All schemes listed here are believed to provide security in the presence of a cryptographically relevant quantum computer.

\[Note to the reader: This specification refers to the NIST PQC draft standards FIPS 203, FIPS 204, and FIPS 205 as if they were a final specification.
This is a temporary solution until the final versions of these documents are available.
The goal is to provide a sufficiently precise specification of the algorithms already at the draft stage of this specification, so that it is possible for implementers to create interoperable implementations.
Furthermore, we want to point out that, depending on possible future changes to the draft standards by NIST, this specification may be updated as soon as corresponding information becomes available.\]

### ML-KEM {#mlkem-intro}

ML-KEM [FIPS-203] is based on the hardness of solving the learning-with-errors problem in module lattices (MLWE).
The scheme is believed to provide security against cryptanalytic attacks by classical as well as quantum computers.
This specification defines ML-KEM only in composite combination with ECC-based encryption schemes in order to provide a pre-quantum security fallback.

### ML-DSA {#mldsa-intro}

ML-DSA [FIPS-204] is a signature scheme that, like ML-KEM, is based on the hardness of solving the Learning With Errors problem and a variant of the Short Integer Solution problem in module lattices (MLWE and SelfTargetMSIS).
Accordingly, this specification only defines ML-DSA in composite combination with ECC-based signature schemes.

## Elliptic Curve Cryptography

The ECC-based encryption is defined here as a KEM.
This is in contrast to {{I-D.ietf-openpgp-crypto-refresh}} where the ECC-based encryption is defined as a public-key encryption scheme.

All elliptic curves for the use in the composite combinations are taken from {{I-D.ietf-openpgp-crypto-refresh}}.

For interoperability this extension offers CRYSTALS-* in composite combinations with the NIST curves P-256, P-384 defined in {{SP800-186}} and the Brainpool curves brainpoolP256r1, brainpoolP384r1 defined in {{RFC5639}}.


# Preliminaries

This section provides some preliminaries for the definitions in the subsequent sections.

## Elliptic curves

### SEC1 EC Point Wire Format {#sec1-format}

Elliptic curve points of the generic prime curves are encoded using the SEC1 (uncompressed) format as the following octet string:

    B = 04 || X || Y

where `X` and `Y` are coordinates of the elliptic curve point `P = (X, Y)`, and each coordinate is encoded in the big-endian format and zero-padded to the adjusted underlying field size.
The adjusted underlying field size is the underlying field size rounded up to the nearest 8-bit boundary, as noted in the "Field size" column in {{tab-ecdh-nist-artifacts}}, {{tab-ecdh-brainpool-artifacts}}, or {{tab-ecdsa-artifacts}}.
This encoding is compatible with the definition given in [SEC1].

### Measures to Ensure Secure Implementations

In the following measures are described that ensure secure implementations according to existing best practices and standards defining the operations of Elliptic Curve Cryptography.

Even though the zero point, also called the point at infinity, may occur as a result of arithmetic operations on points of an elliptic curve, it MUST NOT appear in any ECC data structure defined in this document.

Furthermore, when performing the explicitly listed operations in {{ecdh-kem}} it is REQUIRED to follow the specification and security advisory mandated from the respective elliptic curve specification.


# Supported Public Key Algorithms

This section specifies the composite ML-KEM + ECC and ML-DSA + ECC schemes.
All of these schemes are fully specified via their algorithm ID, i.e., they are not parametrized.

## Algorithm Specifications

For encryption, the following composite KEM schemes are specified:

{: title="KEM algorithm specifications" #kem-alg-specs}
ID                    | Algorithm                          | Requirement | Definition
---------------------:| ---------------------------------- | ----------- | --------------------
TBD                   | ML-KEM-512  + ECDH-NIST-P-256      | MAY         | {{ecc-mlkem}}
TBD                   | ML-KEM-768  + ECDH-NIST-P-384      | MAY         | {{ecc-mlkem}}
TBD                   | ML-KEM-1024 + ECDH-NIST-P-384      | MAY         | {{ecc-mlkem}}
TBD                   | ML-KEM-768  + ECDH-brainpoolP256r1 | MAY         | {{ecc-mlkem}}
TBD                   | ML-KEM-1024 + ECDH-brainpoolP384r1 | MAY         | {{ecc-mlkem}}

For signatures, the following (composite) signature schemes are specified:

{: title="Signature algorithm specifications" #sig-alg-specs}
ID                    | Algorithm                          | Requirement | Definition
---------------------:| ---------------------------------- | ----------- | --------------------
TBD                   | ML-DSA-44 + ECDSA-NIST-P-256       | MAY         | {{ecc-mldsa}}
TBD                   | ML-DSA-65 + ECDSA-NIST-P-384       | MAY         | {{ecc-mldsa}}
TBD                   | ML-DSA-87 + ECDSA-NIST-P-384       | MAY         | {{ecc-mldsa}}
TBD                   | ML-DSA-65 + ECDSA-brainpoolP256r1  | MAY         | {{ecc-mldsa}}
TBD                   | ML-DSA-87 + ECDSA-brainpoolP384r1  | MAY         | {{ecc-mldsa}}

### Experimental Codepoints for Interop Testing

\[ Note: this section to be removed before publication \]

Algorithms indicated as MAY are not assigned a codepoint in the current state of the draft since there are not enough private/experimental code points available to cover all newly introduced public-key algorithm identifiers.

The use of private/experimental codepoints during development are intended to be used in non-released software only, for experimentation and interop testing purposes only.
An OpenPGP implementation MUST NOT produce a formal release using these experimental codepoints.
This draft will not be sent to IANA without every listed algorithm having a non-experimental codepoint.

# Algorithm Combinations

## Composite KEMs

The ML-KEM + ECC public-key encryption involves both the ML-KEM and an ECC-based KEM in an a priori non-separable manner.
This is achieved via KEM combination, i.e. both key encapsulations/decapsulations are performed in parallel, and the resulting key shares are fed into a key combiner to produce a single shared secret for message encryption.

## Parallel Public-Key Encryption {#no-pq-t-parallel-encryption}

TODO: keep this section or refer to the main PQC draft?

The OpenPGP protocol inherently supports parallel encryption to different keys of the same recipient.
Implementations MUST NOT encrypt a message with a classical/traditional public-key encryption key of a recipient if it is encrypted with a PQ/T key of the same recipient.

## Composite Signatures

The ML-DSA + ECC signature consists of independent ML-DSA and ECC signatures, and an implementation MUST successfully validate both signatures to state that the ML-DSA + ECC signature is valid.

## Multiple Signatures {#multiple-signatures}

TODO: keep this section or refer to the main PQC draft?

The OpenPGP message format allows multiple signatures of a message, i.e. the attachment of multiple signature packets.

An implementation MAY sign a message with a traditional key and a PQ(/T) key from the same sender.
This ensures backwards compatibility due to {{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.5, since a legacy implementation without PQ(/T) support can fall back on the traditional signature.

Newer implementations with PQ(/T) support MAY ignore the traditional signature(s) during validation.

Implementations SHOULD consider the message correctly signed if at least one of the non-ignored signatures validates successfully.

\[Note to the reader: The last requirement, that one valid signature is sufficient to identify a message as correctly signed, is an interpretation of {{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.5.\]

# Composite KEM schemes

## Building Blocks

### ECC-Based KEMs {#ecc-kem}

In this section we define the encryption, decryption, and data formats for the ECDH component of the composite algorithms.

{{tab-ecdh-nist-artifacts}} and {{tab-ecdh-brainpool-artifacts}} describe the ECC-KEM parameters and artifact lengths.


{: title="NIST curves parameters and artifact lengths" #tab-ecdh-nist-artifacts}
|                        | NIST P-256                                             | NIST P-384                                             |
|------------------------|--------------------------------------------------------|--------------------------------------------------------|
| Algorithm ID reference | TBD ML-KEM-512 + ECDH-NIST-P-256                       | TBD ML-KEM-768/ML-KEM-1024 + ECDH-NIST-P-384           |
| Field size             | 32 octets                                              | 48 octets                                              |
| ECC-KEM                | ecdhKem ({{ecdh-kem}})                                 | ecdhKem ({{ecdh-kem}})                                 |
| ECDH public key        | 65 octets of SEC1-encoded public point                 | 97 octets of SEC1-encoded public point                 |
| ECDH secret key        | 32 octets big-endian encoded secret scalar             | 48 octets big-endian encoded secret scalar             |
| ECDH ephemeral         | 65 octets of SEC1-encoded ephemeral point              | 97 octets of SEC1-encoded ephemeral point              |
| ECDH share             | 65 octets of SEC1-encoded shared point                 | 97 octets of SEC1-encoded shared point                 |
| Key share              | 32 octets                                              | 48 octets                                              |
| Hash                   | SHA3-256                                               | SHA3-384                                               |

{: title="Brainpool curves parameters and artifact lengths" #tab-ecdh-brainpool-artifacts}
|                        | brainpoolP256r1                                        | brainpoolP384r1                                        |
|------------------------|--------------------------------------------------------|--------------------------------------------------------|
| Algorithm ID reference | TBD (ML-KEM-768 + ECDH-brainpoolP256r1)                | TBD (ML-KEM-1024 + ECDH-brainpoolP384r1)               |
| Field size             | 32 octets                                              | 48 octets                                              |
| ECC-KEM                | ecdhKem ({{ecdh-kem}})                                 | ecdhKem ({{ecdh-kem}})                                 |
| ECDH public key        | 65 octets of SEC1-encoded public point                 | 97 octets of SEC1-encoded public point                 |
| ECDH secret key        | 32 octets big-endian encoded secret scalar             | 48 octets big-endian encoded secret scalar             |
| ECDH ephemeral         | 65 octets of SEC1-encoded ephemeral point              | 97 octets of SEC1-encoded ephemeral point              |
| ECDH share             | 65 octets of SEC1-encoded shared point                 | 97 octets of SEC1-encoded shared point                 |
| Key share              | 32 octets                                              | 64 octets                                              |
| Hash                   | SHA3-256                                               | SHA3-512                                               |

The SEC1 format for point encoding is defined in {{sec1-format}}.

The various procedures to perform the operations of an ECC-based KEM are defined in the following subsections.
Specifically, each of these subsections defines the instances of the following operations:

    (eccCipherText, eccKeyShare) <- ECC-KEM.Encaps(eccPublicKey)

and

    (eccKeyShare) <- ECC-KEM.Decaps(eccSecretKey, eccCipherText, eccPublicKey)

To instantiate `ECC-KEM`, one must select a parameter set from {{tab-ecdh-nist-artifacts}} or {{tab-ecdh-brainpool-artifacts}}.


#### ECDH-KEM {#ecdh-kem}

The operation `ecdhKem.Encaps()` is defined as follows:

 1. Generate an ephemeral key pair {`v`, `V=vG`} as defined in {{SP800-186}} or {{RFC5639}} where `v` is a random scalar with `0 < v < n`, `n` being the base point order of the elliptic curve domain parameters

 2. Compute the shared point `S = vR`, where `R` is the component public key `eccPublicKey`, according to {{SP800-186}} or {{RFC5639}}

 3. Extract the `X` coordinate from the SEC1 encoded point `S = 04 || X || Y` as defined in section {{sec1-format}}

 4. Set the output `eccCipherText` to the SEC1 encoding of `V`

 5. Set the output `eccKeyShare` to `Hash(X || eccCipherText || eccPublicKey)`, with `Hash` chosen according to {{tab-ecdh-nist-artifacts}} or {{tab-ecdh-brainpool-artifacts}}

The operation `ecdhKem.Decaps()` is defined as follows:

 1. Compute the shared Point `S` as `rV`, where `r` is the `eccSecretKey` and `V` is the `eccCipherText`, according to {{SP800-186}} or {{RFC5639}}

 2. Extract the `X` coordinate from the SEC1 encoded point `S = 04 || X || Y` as defined in section {{sec1-format}}

 3. Set the output `eccKeyShare` to `Hash(X || eccCipherText || eccPublicKey)`, with `Hash` chosen according to {{tab-ecdh-nist-artifacts}} or {{tab-ecdh-brainpool-artifacts}}

### ML-KEM {#mlkem-ops}

ML-KEM features the following operations:

    (mlkemCipherText, mlkemKeyShare) <- ML-KEM.Encaps(mlkemPublicKey)

and

    (mlkemKeyShare) <- ML-KEM.Decaps(mlkemCipherText, mlkemSecretKey)

The above are the operations `ML-KEM.Encaps` and `ML-KEM.Decaps` defined in [FIPS-203].
Note that `mlkemPublicKey` is the encapsulation and `mlkemSecretKey` is the decapsulation key.

ML-KEM has the parametrization with the corresponding artifact lengths in octets as given in {{tab-mlkem-artifacts}}.
All artifacts are encoded as defined in [FIPS-203].

{: title="ML-KEM parameters artifact lengths in octets" #tab-mlkem-artifacts}
Algorithm ID reference | ML-KEM      | Public key | Secret key | Ciphertext | Key share
----------------------:| ----------- | ---------- | ---------- | ---------- | ---------
TBD                    | ML-KEM-512  | 800        | 1632       | 768        | 32 
TBD                    | ML-KEM-768  | 1184       | 2400       | 1088       | 32
TBD                    | ML-KEM-1024 | 1568       | 3168       | 1568       | 32

To instantiate `ML-KEM`, one must select a parameter set from the column "ML-KEM" of {{tab-mlkem-artifacts}}.

The procedure to perform `ML-KEM.Encaps()` is as follows:

 1. Invoke `(mlkemCipherText, mlkemKeyShare) <- ML-KEM.Encaps(mlkemPublicKey)`, where `mlkemPublicKey` is the recipient's public key

 2. Set `mlkemCipherText` as the ML-KEM ciphertext

 3. Set `mlkemKeyShare` as the ML-KEM symmetric key share

The procedure to perform `ML-KEM.Decaps()` is as follows:

 1. Invoke `mlkemKeyShare <-  ML-KEM.Decaps(mlkemCipherText, mlkemSecretKey)`

 2. Set `mlkemKeyShare` as the ML-KEM symmetric key share

## Composite Encryption Schemes with ML-KEM {#ecc-mlkem}

{{kem-alg-specs}} specifies the following ML-KEM + ECC composite public-key encryption schemes:

{: title="ML-KEM + ECC composite schemes" #tab-mlkem-ecc-composite}
Algorithm ID reference                   | ML-KEM       | ECC-KEM   | ECC-KEM curve
----------------------------------------:| ------------ | --------- | --------------
TBD (ML-KEM-512 + ECDH-NIST-P-256)       | ML-KEM-512   | ecdhKem   | NIST P-256
TBD (ML-KEM-768 + ECDH-NIST-P-384)       | ML-KEM-768   | ecdhKem   | NIST P-384
TBD (ML-KEM-1024 + ECDH-NIST-P-384)      | ML-KEM-1024  | ecdhKem   | NIST P-384
TBD (ML-KEM-768 + ECDH-brainpoolP256r1)  | ML-KEM-768   | ecdhKem   | brainpoolP256r1
TBD (ML-KEM-1024 + ECDH-brainpoolP384r1) | ML-KEM-1024  | ecdhKem   | brainpoolP384r1

The ML-KEM + ECC composite public-key encryption schemes are built according to the following principal design:

 - The ML-KEM encapsulation algorithm is invoked to create a ML-KEM ciphertext together with a ML-KEM symmetric key share.

 - The encapsulation algorithm of an ECDH-KEM is invoked to create an ECC ciphertext together with an ECC symmetric key share.

 - A Key-Encryption-Key (KEK) is computed as the output of a key combiner that receives as input both of the above created symmetric key shares and the protocol binding information.

 - The session key for content encryption is then wrapped as described in {{RFC3394}} using AES-256 as algorithm and the KEK as key.

 - The PKESK package's algorithm-specific parts are made up of the ML-KEM ciphertext, the ECC ciphertext, and the wrapped session key.

### Fixed information {#kem-fixed-info}

For the composite KEM schemes defined in {{kem-alg-specs}} the following procedure, justified in TBD:(refer to main draft), MUST be used to derive a string to use as binding between the KEK and the communication parties.

    //   Input:
    //   algID     - the algorithm ID encoded as octet

    fixedInfo = algID || eccCipherText || mlkemCipherText

### Key combiner {#kem-key-combiner}

TODO:simply reference the main draft for the key combiner ?

For the composite KEM schemes defined in {{kem-alg-specs}} the following procedure MUST be used to compute the KEK that wraps a session key.
The construction is a one-step key derivation function compliant to {{SP800-56C}} Section 4, based on KMAC256 {{SP800-185}}.
It is given by the following algorithm, which computes the key encryption key `KEK` that is used to wrap, i.e., encrypt, the session key.

    //   multiKeyCombine(eccKeyShare, eccCipherText,
    //                   mlkemKeyShare, mlkemCipherText,
    //                   fixedInfo, oBits)
    //
    //   Input:
    //   eccKeyShare     - the ECC key share encoded as an octet string
    //   eccCipherText   - the ECC ciphertext encoded as an octet string
    //   mlkemKeyShare   - the ML-KEM key share encoded as an octet string
    //   mlkemCipherText - the ML-KEM ciphertext encoded as an octet string
    //   fixedInfo       - algID || eccCipherText || mlkemCipherText
    //   oBits           - the size of the output keying material in bits
    //
    //   Constants:
    //   domSeparation       - the UTF-8 encoding of the string
    //                         "OpenPGPCompositeKeyDerivationFunction"
    //   counter             - the 4 byte value 00 00 00 01
    //   customizationString - the UTF-8 encoding of the string "KDF"

    
    encData = counter || eccKeyShare ||  mlkemKeyShare || fixedInfo

    KEK = KMAC256(domSeparation, encData, oBits, customizationString)
    return KEK

Here, the parameters to KMAC256 appear in the order as specified in {{SP800-186}}, Section 4, i.e., the key `K`, main input data `X`, requested output length `L`, and optional customization string `S` in that order.

The value of `domSeparation` is the UTF-8 encoding of the string "OpenPGPCompositeKeyDerivationFunction" and MUST be the following octet sequence:

    domSeparation := 4F 70 65 6E 50 47 50 43 6F 6D 70 6F 73 69 74 65
                     4B 65 79 44 65 72 69 76 61 74 69 6F 6E 46 75 6E
                     63 74 69 6F 6E

The value of `counter` MUST be set to the following octet sequence:

    counter :=  00 00 00 01

The value of `customizationString` is the UTF-8 encoding of the string "KDF" and MUST be set to the following octet sequence:

    customizationString := 4B 44 46

### Key generation procedure {#ecc-mlkem-generation}

The implementation MUST independently generate the ML-KEM and the ECC component keys.
ML-KEM key generation follows the specification [FIPS-203] and the artifacts are encoded as fixed-length octet strings as defined in {{mlkem-ops}}.
For ECC this is done following the relative specification in {{RFC7748}}, {{SP800-186}}, or {{RFC5639}}, and encoding the outputs as fixed-length octet strings in the format specified in {{tab-ecdh-nist-artifacts}} or {{tab-ecdh-brainpool-artifacts}}.

### Encryption procedure {#ecc-mlkem-encryption}

The procedure to perform public-key encryption with a ML-KEM + ECC composite scheme is as follows:

 1. Take the recipient's authenticated public-key packet `pkComposite` and `sessionKey` as input

 2. Parse the algorithm ID from `pkComposite`

 3. Extract the `eccPublicKey` and `mlkemPublicKey` component from the algorithm specific data encoded in `pkComposite` with the format specified in {{mlkem-ecc-key}}.

 4. Instantiate the ECC-KEM and the ML-KEM depending on the algorithm ID according to {{tab-mlkem-ecc-composite}}

 5. Compute `(eccCipherText, eccKeyShare) := ECC-KEM.Encaps(eccPublicKey)`

 6. Compute `(mlkemCipherText, mlkemKeyShare) := ML-KEM.Encaps(mlkemPublicKey)`

 7. Compute `fixedInfo` as specified above in {{kem-fixed-info}}: TODO: Fix the refered doc here to make sure it is the same as above to comply with 56C one step KDF using KMAC. Z is either eccKeyShare, mlkemKeyShare or both. Z does not contain any other information. 

 8. Compute KEK = KMAC256(domSeparation, encData, oBits, customizationString) as defined above.

 9. Compute `C := AESKeyWrap(KEK, sessionKey)` with AES-256 as per {{RFC3394}} that includes a 64 bit integrity check

 10. Output the algorithm specific part of the PKESK as `eccCipherText || mlkemCipherText (|| symAlgId) || len(C) || C`, where both `symAlgId` and `len(C)` are single octet fields and `symAlgId` denotes the symmetric algorithm ID used and is present only for a v3 PKESK

### Decryption procedure

The procedure to perform public-key decryption with a ML-KEM + ECC composite scheme is as follows:

 1. Take the matching PKESK and own secret key packet as input

 2. From the PKESK extract the algorithm ID and the `encryptedKey`, i.e., the wrapped session key

 3. Check that the own and the extracted algorithm ID match

 4. Parse the `eccSecretKey` and `mlkemSecretKey` from the algorithm specific data of the own secret key encoded in the format specified in {{mlkem-ecc-key}}

 5. Instantiate the ECC-KEM and the ML-KEM depending on the algorithm ID according to {{tab-mlkem-ecc-composite}}

 6. Parse `eccCipherText`, `mlkemCipherText`, and `C` from `encryptedKey` encoded as `eccCipherText || mlkemCipherText (|| symAlgId) || len(C) || C` as specified in {{ecc-mlkem-pkesk}}, where `symAlgId` is present only in the case of a v3 PKESK.

 7. Compute `(eccKeyShare) := ECC-KEM.Decaps(eccCipherText, eccSecretKey, eccPublicKey)`

 8. Compute `(mlkemKeyShare) := ML-KEM.Decaps(mlkemCipherText, mlkemSecretKey)`

 9. Compute `fixedInfo` as specified above. 

 10. Compute `KEK = KMAC256(domSeparation, encData, oBits, customizationString)` as defined above. 

 11. Compute `sessionKey := AESKeyUnwrap(KEK, C)`  with AES-256 as per {{RFC3394}}, aborting if the 64 bit integrity check fails

 12. Output `sessionKey`

## Packet specifications

### Public-Key Encrypted Session Key Packets (Tag 1) {#ecc-mlkem-pkesk}

The algorithm-specific fields consists of the output of the encryption procedure described in {{ecc-mlkem-encryption}}:

 - A fixed-length octet string representing an ECC ephemeral public key in the format associated with the curve as specified in {{ecc-kem}}.

 - A fixed-length octet string of the ML-KEM ciphertext, whose length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

 - A one-octet size of the following fields.

 - Only in the case of a v3 PKESK packet: a one-octet symmetric algorithm identifier.

 - The wrapped session key represented as an octet string.

Note that like in the case of the algorithms X25519 and X448 specified in {{I-D.ietf-openpgp-crypto-refresh}}, for the ML-KEM composite schemes, in the case of a v3 PKESK packet, the symmetric algorithm identifier is not encrypted.
Instead, it is placed in plaintext after the `mlkemCipherText` and before the length octet preceding the wrapped session key.
In the case of v3 PKESK packets for ML-KEM composite schemes, the symmetric algorithm used MUST be AES-128, AES-192 or AES-256 (algorithm ID 7, 8 or 9).

In the case of a v3 PKESK, a receiving implementation MUST check if the length of the unwrapped symmetric key matches the symmetric algorithm identifier, and abort if this is not the case.


### Key Material Packets {#mlkem-ecc-key}

The algorithm-specific public key is this series of values:

 - A fixed-length octet string representing an EC point public key, in the point format associated with the curve specified in {{ecc-kem}}.

 - A fixed-length octet string containing the ML-KEM public key, whose length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

The algorithm-specific secret key is these two values:

 - A fixed-length octet string of the encoded secret scalar, whose encoding and length depend on the algorithm ID as specified in {{ecc-kem}}.

 - A fixed-length octet string containing the ML-KEM secret key, whose length depends on the algorithm ID as specified in {{tab-mlkem-artifacts}}.

# Composite Signature Schemes

## Building blocks

### ECDSA-Based signatures {#ecdsa-signature}

To sign and verify with ECDSA the following operations are defined:

    (ecdsaSignatureR, ecdsaSignatureS) <- ECDSA.Sign(ecdsaSecretKey,
                                                     dataDigest)

and

    (verified) <- ECDSA.Verify(ecdsaPublicKey, ecdsaSignatureR,
                               ecdsaSignatureS, dataDigest)

The public keys MUST be encoded in SEC1 format as defined in section {{sec1-format}}.
The secret key, as well as both values `R` and `S` of the signature MUST each be encoded as a big-endian integer in a fixed-length octet string of the specified size.

The following table describes the ECDSA parameters and artifact lengths:

{: title="ECDSA parameters and artifact lengths in octets" #tab-ecdsa-artifacts}
Algorithm ID reference                  | Curve           | Field size | Public key | Secret key | Signature value R | Signature value S
---------------------------------------:| --------------- | ---------- | ---------- | ---------- | ----------------- | -----------------
TBD (ML-DSA-44 + ECDSA-NIST-P-256)      | NIST P-256      | 32         | 65         | 32         | 32                | 32
TBD (ML-DSA-65 + ECDSA-NIST-P-384)      | NIST P-384      | 48         | 97         | 48         | 48                | 48
TBD (ML-DSA-87 + ECDSA-NIST-P-384)      | NIST P-384      | 48         | 97         | 48         | 48                | 48
TBD (ML-DSA-65 + ECDSA-brainpoolP256r1) | brainpoolP256r1 | 32         | 65         | 32         | 32                | 32
TBD (ML-DSA-87 + ECDSA-brainpoolP384r1) | brainpoolP384r1 | 48         | 97         | 48         | 48                | 48

### ML-DSA signatures {#mldsa-signature}

For ML-DSA signature generation the default hedged version of `ML-DSA.Sign` given in [FIPS-204] is used.
That is, to sign with ML-DSA the following operation is defined:

    (mldsaSignature) <- ML-DSA.Sign(mldsaSecretKey, dataDigest)

For ML-DSA signature verification the algorithm ML-DSA.Verify given in [FIPS-204] is used.
That is, to verify with ML-DSA the following operation is defined:

    (verified) <- ML-DSA.Verify(mldsaPublicKey, dataDigest, mldsaSignature)

ML-DSA has the parametrization with the corresponding artifact lengths in octets as given in {{tab-mldsa-artifacts}}.
All artifacts are encoded as defined in [FIPS-204].

{: title="ML-DSA parameters and artifact lengths in octets" #tab-mldsa-artifacts}
Algorithm ID reference | ML-DSA    | Public key | Secret key | Signature value
----------------------:| --------- | -----------| ---------- | ---------------
TBD                    | ML-DSA-44 | 1312       | 2528       | 2420
TBD                    | ML-DSA-65 | 1952       | 4032       | 3293
TBD                    | ML-DSA-87 | 2592       | 4896       | 4595

## Composite Signature Schemes with ML-DSA {#ecc-mldsa}

### Signature data digest {#mldsa-sig-data-digest}

Signature data (i.e. the data to be signed) is digested prior to signing operations, see {{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.4.
Composite ML-DSA + ECC signatures MUST use the associated hash algorithm as specified in {{tab-mldsa-hash}} for the signature data digest.
Signatures using other hash algorithms MUST be considered invalid.

An implementation supporting a specific ML-DSA + ECC algorithm MUST also support the matching hash algorithm.

{: title="Binding between ML-DSA and signature data digest" #tab-mldsa-hash}
Algorithm ID reference | Hash function | Hash function ID reference
----------------------:| ------------- | --------------------------
TBD (ML-DSA-44 IDs)    | SHA3-256      | 11
TBD (ML-DSA-65 IDs)    | SHA3-384      | 12
TBD (ML-DSA-87 IDs)    | SHA3-512      | 14

### Key generation procedure {#ecc-mldsa-generation}

The implementation MUST independently generate the ML-DSA and the ECC component keys.
ML-DSA key generation follows the specification [FIPS-204] and the artifacts are encoded as fixed-length octet strings as defined in {{mldsa-signature}}.
For ECC this is done following the relative specification in {{RFC7748}}, {{SP800-186}}, or {{RFC5639}}, and encoding the artifacts as specified in {{ecdsa-signature}} as fixed-length octet strings.

### Signature Generation


To sign a message `M` with ML-DSA + ECDSA the following sequence of operations has to be performed:

 1. Generate `dataDigest` according to {{I-D.ietf-openpgp-crypto-refresh}} Section 5.2.4

 2. Create the ECDSA signature over `dataDigest` with `ECDSA.Sign()` from {{ecdsa-signature}}

 3. Create the ML-DSA signature over `dataDigest` with `ML-DSA.Sign()` from {{mldsa-signature}}

 4. Encode the ECDSA and ML-DSA signatures according to the packet structure given in {{ecc-mldsa-sig-packet}}.

### Signature Verification


To verify a ML-DSA + ECDSA signature the following sequence of operations has to be performed:

 1. Verify the ECDSA signature with `ECDSA.Verify()` from {{ecdsa-signature}}

 2. Verify the ML-DSA signature with `ML-DSA.Verify()` from {{mldsa-signature}}

As specified in {{composite-signatures}} an implementation MUST validate both signatures, i.e. ECDSA and ML-DSA, successfully to state that a composite ML-DSA + ECC signature is valid.

## Packet Specifications

### Signature Packet (Tag 2) {#ecc-mldsa-sig-packet}

The composite ML-DSA + ECC schemes MUST be used only with v6 signatures, as defined in [I-D.ietf-openpgp-crypto-refresh].


The algorithm-specific v6 signature parameters for ML-DSA + ECDSA signatures consists of:

 - A fixed-length octet string of the big-endian encoded ECDSA value `R`, whose length depends on the algorithm ID as specified in {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string of the big-endian encoded ECDSA value `S`, whose length depends on the algorithm ID as specified in {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string of the ML-DSA signature value, whose length depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

### Key Material Packets

The composite ML-DSA + ECC schemes MUST be used only with v6 keys, as defined in [I-D.ietf-openpgp-crypto-refresh].

The algorithm-specific public key for ML-DSA + ECDSA keys is this series of values:

 - A fixed-length octet string representing the ECDSA public key in SEC1 format, as specified in section {{sec1-format}} and with length specified in {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA public key, whose length depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.

The algorithm-specific secret key for ML-DSA + ECDSA keys is this series of values:

 - A fixed-length octet string representing the ECDSA secret key as a big-endian encoded integer, whose length depends on the algorithm used as specified in {{tab-ecdsa-artifacts}}.

 - A fixed-length octet string containing the ML-DSA secret key, whose length depends on the algorithm ID as specified in {{tab-mldsa-artifacts}}.





# Security Considerations

TBD



# IANA Considerations

IANA is requested to add the algorithm IDs defined in {{iana-pubkey-algos}} to the existing registry `OpenPGP Public Key Algorithms`.
The field specifications enclosed in brackets for the ML-KEM + ECDH composite algorithms denote fields that are only conditionally contained in the data structure.


{: title="IANA updates for registry 'OpenPGP Public Key Algorithms'" #iana-pubkey-algos}
ID     | Algorithm           | Public Key Format                                                                                                      | Secret Key Format                                                                                                      | Signature Format                                                                                                 | PKESK Format                                                                                                                                                                                           | Reference
---  : | -----               | ---------:                                                                                                             | --------:                                                                                                              | --------:                                                                                                        | -----:                                                                                                                                                                                                 | -----:
TBD    | ML-DSA-65 + TBD | 32 octets TBD public key , 1952 octets ML-DSA-65 public key ({{tab-mldsa-artifacts}})     | 32 octets TBD secret key , 4032  octets ML-DSA-65 secret ({{tab-mldsa-artifacts}})        | 64 octets TBD signature , 3293 octets ML-DSA-65 signature ({{tab-mldsa-artifacts}}) | N/A                                                                                                                                                                                                    | {{ecc-mldsa}}
TBD    | ML-DSA-87 + TBD   | 57 octets TBD public key ,  2592 octets ML-DSA-87 public key ({{tab-mldsa-artifacts}})      | 57 octets TBD secret key , 4896 octets ML-DSA-87 secret ({{tab-mldsa-artifacts}})           | 114 octets TBD signature, 4595 octets ML-DSA-87 signature ({{tab-mldsa-artifacts}})  | N/A                                                                                                                                                                                                    | {{ecc-mldsa}}
TODO: The IANA Cosiderations section is not ready. 

# Changelog


# Contributors

Stephan Ehlen (BSI)<br>
Carl-Daniel Hailfinger (BSI)<br>
Andreas Huelsing (TU Eindhoven)

--- back

# Test Vectors

TBD

## Sample v6 PQC Subkey Artifacts

TBD
## V4 PQC Subkey Artifacts

TBD

# Acknowledgments
{:numbered="false"}

