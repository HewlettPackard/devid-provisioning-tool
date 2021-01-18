# DevID Certificate Fields
## DevID
The DevID certificate **MUST** contain the following subset of fields from RFC-5280:
- [ ] `serialNumber`: Certificate serial number (this is not a device serial number):
  1. **MUST** be a unique (per CA) integer.
  2. **MUST** be >= 64-bits AND <= 160-bits in
  size.
  1. **MUST** be non-negative per RFC-5280.
- Validity:
  - [ ] `notBefore`: The earliest time a certificate may be used. This **SHALL** be the date the IDevID/IAK certificate is created.
  - [ ] `notAfter`: The latest time a DevID certificate is expected to be used. Devices possessing an IDevID or IAK certificate are expected to operate indefinitely into the future and SHOULD use the value *"99991231235959Z"*. Solutions verifying an IDevID/IAK certificate are expected to accept this value indefinitely. Any other value in a DevID notAfter field is expected to be treated as specified in RFC-5280.
- [ ] `Subject`:
  - [ ] IDevID/IAK : In compliance with 802.1AR **SHOULD** include Serial Number attribute.
  - [ ] LDevID/LAK: In accordance with local CA policy.

Extensions:
- [ ] `subjectAltName`:
  - `id-on-hardwareModuleName` (OID: `1.3.6.1.5.5.7.8.4`)
  - `HardwareModuleName`:
    ```
    HardwareModuleName ::= SEQUENCE {
        hwType OBJECT IDENTIFIER,
        hwSerialNum OCTET STRING
    }
    ```
    **Note:** `hwType` for TPM2 is `2.23.133.1.2`
- [ ] Key Usage: `digitalSignature` (DevID/AK)
- [ ] Extended Key Usage: **SHOULD** be populated with the one TCG OID appropriate for the type of key used, either `TCG-CE-FixedTPM` or `TCG-CE-FixedTPM-RestrictedKey`.

- [ ] Certificate Policy (v3 extension): certificate policy URL **MUST** be present.


## IDevID/IAK
- [ ] `Subject`/`X520SerialNumber`: **MUST** contain "device" serial number
- [ ] `Extensions`/`subjectAltName`: don't need to be `critical` but **MUST** contain a value to identify the TPM with the
HardwareModuleName and HwType
- [ ] **SHALL** contain a TCG OID that represents TPM Version 2 in the `hwType` field together with a value in `hwSerialNum`
    - The `hwSerialNum` value is an *OCTET STRING* and **SHALL** be constructed by one of two methods:
      1. When the TPM has an EK Certificate, the `hwSerialNum` is created by concatenating three ASCII values: The TCG TPM Manufacturer code, the EK Authority Key Identifier and the EK CertificateSerialNumber. These three fields **SHALL** be separated by a colon (`:`) character. The three values **SHALL** be listed in the order specified.
      2. When the TPM does not have an EK certificate, the `hwSerialNum` is a digest of the EK Certificate public key.






## LDevID/LAK
If an LDevID/LAK is created and an IDevID/IAK exists, then:
1. A `Subject` name field **SHOULD** be included in the LDevID/LAK certificate and **SHOULD** match the IDevID/IAK `Subject`;
2. The `subjectAltName` **SHOULD** include the entire `subjectAltName` from the IDevID/IAK certificate.

**Note:** If the LDevID/LAK creator decides to leave the `Subject` name field empty, the `subjectAltName` extension **MUST** be `critical` in accordance with RFC 5280.

**Note:** For LDevID/LAK creation, the subject field **SHOULD** match the IDevID/IAK.



---
# Assumptions:
- [ ] `TCG-CE-FixedTPM-RestrictedKey` is `tcg-cap-verifiedTPMRestricted`
- [ ] `TCG-CE-FixedTPM` is `tcg-cap-verifiedTPMFixed`
- [ ] `tcg-cap-verifiedTPMResidency`, `tcg-cap-verifiedTPMFixed` and `tcg-cap-verifiedTPMRestricted` **are not** extensions itself, but *KeyPurposeId* values to be used in the *Extended Key Usage* extension

---
# Questions:
- Does the "device" at IDevID/IAK subject refers to "TPM device" or "PC device"?
- Where is `hwModuleName` described?
