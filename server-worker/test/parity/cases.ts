// Structural mutation catalogue for the parity harness. Every case is verified by both implementations.
import {
  buildChain, toCase, keyDescription, hwList, swList, appId, rootOfTrust, attestationExt, basicConstraintsExt, name, ecKey, rsaKey, pop, sign,
  seq, set, octet, bool, utf8, printable, ctx, ctxPrimitive, int, enumerated, concat, tlv, b64, b64url, CHALLENGE, NOW, SIGNER, PACKAGE,
} from "./synthetic.ts";
import type { Case, Built } from "./synthetic.ts";
import { integerContent } from "./der-writer.ts";

const DAY = 86_400_000;
const enc = (s: string) => new TextEncoder().encode(s);

export async function structuralCases(): Promise<Case[]> {
  const out: Case[] = [];
  const base = await buildChain();
  const keys = base.keys;
  const kdCase = async (id: string, kd: Uint8Array, extra: Parameters<typeof toCase>[2] = {}) => {
    const built = await buildChain({ kd }, keys);
    out.push(await toCase(id, built, extra));
  };
  const chainCase = async (id: string, opts: Parameters<typeof buildChain>[0], extra: Parameters<typeof toCase>[2] = {}) => {
    const built = await buildChain(opts, keys);
    out.push(await toCase(id, built, extra));
  };

  out.push(await toCase("syn-baseline", base));
  out.push(await toCase("syn-baseline-remote", await buildChain({ remote: true }, keys)));
  out.push(await toCase("syn-remote-strongbox", await buildChain({ remote: true, remoteLevel: "StrongBox", kd: keyDescription({ attestationSecurityLevel: enumerated(2), keyMintSecurityLevel: enumerated(2) }) }, keys)));
  out.push(await toCase("syn-remote-strongbox-tee-claim", await buildChain({ remote: true, remoteLevel: "StrongBox" }, keys)));
  out.push(await toCase("syn-remote-tee-strongbox-claim", await buildChain({ remote: true, kd: keyDescription({ attestationSecurityLevel: enumerated(2), keyMintSecurityLevel: enumerated(2) }) }, keys)));
  await chainCase("syn-factory-strongbox", { intermediateSubject: name(["serialNumber", "e18c4f2ca699739a"], ["title", "StrongBox"]), kd: keyDescription({ attestationSecurityLevel: enumerated(2), keyMintSecurityLevel: enumerated(2) }) });
  await chainCase("syn-factory-strongbox-attestation-name", { attestationSubject: name(["serialNumber", "decafbad"], ["title", "strongBOX"]), kd: keyDescription({ attestationSecurityLevel: enumerated(2), keyMintSecurityLevel: enumerated(2) }) });
  await chainCase("syn-factory-strongbox-claim-on-tee", { kd: keyDescription({ attestationSecurityLevel: enumerated(2), keyMintSecurityLevel: enumerated(2) }) });

  // --- KeyDescription structure ---
  await kdCase("kd-7-elements", seq(int(300), enumerated(1), int(300), enumerated(1), octet(CHALLENGE), octet(new Uint8Array()), swList()));
  await kdCase("kd-9-elements", concat(keyDescription().subarray(0, 0), seq(int(300), enumerated(1), int(300), enumerated(1), octet(CHALLENGE), octet(new Uint8Array()), swList(), hwList(), int(1))));
  await kdCase("kd-level-unknown-5", keyDescription({ attestationSecurityLevel: enumerated(5), keyMintSecurityLevel: enumerated(5) }));
  await kdCase("kd-level-as-integer", keyDescription({ attestationSecurityLevel: int(1) }));
  await kdCase("kd-level-negative", keyDescription({ attestationSecurityLevel: enumerated(-1), keyMintSecurityLevel: enumerated(-1) }));
  await kdCase("kd-version-as-enumerated", keyDescription({ rawBody: [enumerated(300), enumerated(1), int(300), enumerated(1), octet(CHALLENGE), octet(new Uint8Array()), swList(), hwList()] }));
  await kdCase("kd-challenge-utf8string", keyDescription({ rawBody: [int(300), enumerated(1), int(300), enumerated(1), utf8("x"), octet(new Uint8Array()), swList(), hwList()] }));
  await kdCase("kd-challenge-wrong", keyDescription({ challenge: Uint8Array.from(CHALLENGE, (x) => x ^ 1) }));
  await kdCase("kd-challenge-empty", keyDescription({ challenge: new Uint8Array() }));
  await kdCase("kd-challenge-prefix", keyDescription({ challenge: CHALLENGE.subarray(0, 56) }));
  await kdCase("kd-sw-as-set", keyDescription({ sw: set() }));
  await kdCase("kd-hw-as-set", keyDescription({ hw: set() }));
  await kdCase("kd-uniqueid-nonempty", keyDescription({ uniqueId: new Uint8Array(16).fill(9) }));
  await kdCase("kd-trailing-bytes-in-ext", concat(keyDescription(), Uint8Array.of(0)));
  await kdCase("kd-ext-empty", new Uint8Array());
  await kdCase("kd-ext-not-sequence", octet(CHALLENGE));
  await kdCase("kd-nonminimal-length", (() => {
    const kd = keyDescription();
    // rewrite outer length as long-form 0x82 xx xx
    const len = kd.length - (kd[1] & 0x80 ? 2 + (kd[1] & 0x7f) : 2);
    const hdr = kd[1] & 0x80 ? 2 + (kd[1] & 0x7f) : 2;
    return concat(Uint8Array.of(0x30, 0x82, len >> 8, len & 0xff), kd.subarray(hdr));
  })());
  await kdCase("kd-indefinite-length-ber", (() => {
    const kd = keyDescription();
    const hdr = kd[1] & 0x80 ? 2 + (kd[1] & 0x7f) : 2;
    return concat(Uint8Array.of(0x30, 0x80), kd.subarray(hdr), Uint8Array.of(0, 0));
  })());

  // --- AuthorizationList structure ---
  await kdCase("al-unknown-tag-999", keyDescription({ hw: hwList({}, [ctx(999, int(1))]) }));
  await kdCase("al-unknown-tag-7", keyDescription({ hw: hwList({}, [ctx(7, int(1))]) }));
  await kdCase("al-universal-element", keyDescription({ hw: hwList({}, [int(1)]) }));
  await kdCase("al-implicit-primitive-purpose", keyDescription({ hw: hwList({ 1: null }, [ctxPrimitive(1, Uint8Array.of(2))]) }));
  await kdCase("al-explicit-two-children", keyDescription({ hw: hwList({ 3: null }, [ctx(3, int(256), int(256))]) }));
  await kdCase("al-explicit-empty", keyDescription({ hw: hwList({ 3: null }, [ctx(3)]) }));
  await kdCase("al-application-class-tag", keyDescription({ hw: hwList({ 3: null }, [tlv(1, true, 3, int(256))]) }));
  await kdCase("al-private-class-tag", keyDescription({ hw: hwList({ 3: null }, [tlv(3, true, 3, int(256))]) }));
  await kdCase("al-duplicate-purpose-last-bad", keyDescription({ hw: hwList({}, [ctx(1, set(int(3)))]) }));
  await kdCase("al-duplicate-purpose-last-good", keyDescription({ hw: hwList({ 1: set(int(3)) }, [ctx(1, set(int(2)))]) }));
  await kdCase("al-descending-order", keyDescription({ hw: seq(ctx(704, rootOfTrust()), ctx(702, int(0)), ctx(10, int(1)), ctx(5, set(int(4))), ctx(3, int(256)), ctx(2, int(3)), ctx(1, set(int(2)))) }));
  await kdCase("al-empty-hw", keyDescription({ hw: seq() }));
  await kdCase("al-empty-sw", keyDescription({ sw: seq() }));
  await kdCase("al-purposes-as-sequence", keyDescription({ hw: hwList({ 1: seq(int(2)) }) }));
  await kdCase("al-purposes-non-integer", keyDescription({ hw: hwList({ 1: set(octet(Uint8Array.of(2))) }) }));
  await kdCase("al-purposes-empty-set", keyDescription({ hw: hwList({ 1: set() }) }));
  await kdCase("al-purposes-dup-values", keyDescription({ hw: hwList({ 1: set(int(2), int(2)) }) }));
  await kdCase("al-purposes-missing", keyDescription({ hw: hwList({ 1: null }) }));
  await kdCase("al-algorithm-octet", keyDescription({ hw: hwList({ 2: octet(Uint8Array.of(3)) }) }));
  await kdCase("al-algorithm-enumerated", keyDescription({ hw: hwList({ 2: enumerated(3) }) }));
  await kdCase("al-keysize-nonminimal-int", keyDescription({ hw: hwList({ 3: tlv(0, false, 2, Uint8Array.of(0, 1, 0)) }) }));
  await kdCase("al-keysize-negative", keyDescription({ hw: hwList({ 3: int(-256) }) }));
  await kdCase("al-keysize-huge", keyDescription({ hw: hwList({ 3: int(2n ** 70n) }) }));
  await kdCase("al-digests-two", keyDescription({ hw: hwList({ 5: set(int(4), int(6)) }) }));
  await kdCase("al-curve-2", keyDescription({ hw: hwList({ 10: int(2) }) }));
  await kdCase("al-origin-7", keyDescription({ hw: hwList({ 702: int(7) }) }));
  await kdCase("al-origin-imported", keyDescription({ hw: hwList({ 702: int(2) }) }));
  await kdCase("al-origin-enumerated", keyDescription({ hw: hwList({ 702: enumerated(0) }) }));
  await kdCase("al-origin-missing", keyDescription({ hw: hwList({ 702: null }) }));
  await kdCase("al-origin-in-sw-only", keyDescription({ hw: hwList({ 702: null }), sw: swList({}, [ctx(702, int(0))]) }));
  await kdCase("al-patchlevel-octet", keyDescription({ hw: hwList({ 706: octet(enc("202409")) }) }));
  await kdCase("al-patchlevel-short", keyDescription({ hw: hwList({ 706: int(2024) }) }));
  await kdCase("al-patchlevel-8-digits", keyDescription({ hw: hwList({ 706: int(20240905) }) }));
  await kdCase("al-brand-invalid-utf8", keyDescription({ hw: hwList({ 710: octet(Uint8Array.of(0xff, 0xfe)) }) }));
  await kdCase("al-brand-integer", keyDescription({ hw: hwList({ 710: int(1) }) }));
  await kdCase("al-modulehash-integer", keyDescription({ hw: hwList({}, [ctx(724, int(1))]) }));
  await kdCase("al-noauth-null", keyDescription({ hw: hwList({}, [ctx(503, tlv(0, false, 5, new Uint8Array()))]) }));
  await kdCase("al-noauth-boolean", keyDescription({ hw: hwList({}, [ctx(503, bool(true))]) }));
  await kdCase("al-blockmode-sequence", keyDescription({ hw: hwList({}, [ctx(4, seq(int(1)))]) }));
  await kdCase("al-rsa-exponent-octet", keyDescription({ hw: hwList({}, [ctx(200, octet(Uint8Array.of(1)))]) }));
  await kdCase("al-mldsa-variant", keyDescription({ hw: hwList({}, [ctx(11, int(1))]) }));

  // --- RootOfTrust ---
  await kdCase("rot-2-elements", keyDescription({ hw: hwList({ 704: rootOfTrust({ body: [octet(new Uint8Array(32)), bool(true)] }) }) }));
  await kdCase("rot-5-elements", keyDescription({ hw: hwList({ 704: rootOfTrust({ body: [octet(new Uint8Array(32)), bool(true), enumerated(0), octet(new Uint8Array(32)), int(1)] }) }) }));
  await kdCase("rot-state-9", keyDescription({ hw: hwList({ 704: rootOfTrust({ state: enumerated(9) }) }) }));
  await kdCase("rot-state-integer", keyDescription({ hw: hwList({ 704: rootOfTrust({ state: int(0) }) }) }));
  await kdCase("rot-locked-integer", keyDescription({ hw: hwList({ 704: rootOfTrust({ locked: int(1) }) }) }));
  await kdCase("rot-locked-0x01", keyDescription({ hw: hwList({ 704: rootOfTrust({ locked: bool(true, 0x01) }) }) }));
  await kdCase("rot-locked-false", keyDescription({ hw: hwList({ 704: rootOfTrust({ locked: bool(false) }) }) }));
  await kdCase("rot-unverified", keyDescription({ hw: hwList({ 704: rootOfTrust({ state: enumerated(2) }) }) }));
  await kdCase("rot-self-signed", keyDescription({ hw: hwList({ 704: rootOfTrust({ state: enumerated(1) }) }) }));
  await kdCase("rot-with-hash", keyDescription({ hw: hwList({ 704: rootOfTrust({ hash: octet(new Uint8Array(32)) }) }) }));
  await kdCase("rot-hash-integer", keyDescription({ hw: hwList({ 704: rootOfTrust({ hash: int(1) }) }) }));
  await kdCase("rot-key-utf8", keyDescription({ hw: hwList({ 704: rootOfTrust({ key: utf8("key") }) }) }));
  await kdCase("rot-as-set", keyDescription({ hw: hwList({ 704: set(octet(new Uint8Array(32)), bool(true), enumerated(0)) }) }));
  await kdCase("rot-missing", keyDescription({ hw: hwList({ 704: null }) }));
  await kdCase("rot-in-sw-only", keyDescription({ hw: hwList({ 704: null }), sw: swList({}, [ctx(704, rootOfTrust())]) }));
  await kdCase("rot-boolean-length-2", keyDescription({ hw: hwList({ 704: rootOfTrust({ locked: tlv(0, false, 1, Uint8Array.of(0xff, 0xff)) }) }) }));

  // --- AttestationApplicationId ---
  await kdCase("app-not-octet", keyDescription({ sw: swList({ 709: appId({ wrap: (i) => i }) }) }));
  await kdCase("app-inner-3-elements", keyDescription({ sw: swList({ 709: appId({ body: [set(seq(octet(enc(PACKAGE)), int(1))), set(octet(SIGNER)), int(1)] }) }) }));
  await kdCase("app-inner-1-element", keyDescription({ sw: swList({ 709: appId({ body: [set(seq(octet(enc(PACKAGE)), int(1)))] }) }) }));
  await kdCase("app-packages-as-sequence", keyDescription({ sw: swList({ 709: appId({ body: [seq(seq(octet(enc(PACKAGE)), int(1))), set(octet(SIGNER))] }) }) }));
  await kdCase("app-signatures-as-sequence", keyDescription({ sw: swList({ 709: appId({ body: [set(seq(octet(enc(PACKAGE)), int(1))), seq(octet(SIGNER))] }) }) }));
  await kdCase("app-33-packages", keyDescription({ sw: swList({ 709: appId({ packages: Array.from({ length: 33 }, (_, i) => seq(octet(enc("p" + i)), int(1))) }) }) }));
  await kdCase("app-32-packages", keyDescription({ sw: swList({ 709: appId({ packages: Array.from({ length: 32 }, (_, i) => seq(octet(enc("p" + i)), int(1))) }) }) }));
  await kdCase("app-11-signatures", keyDescription({ sw: swList({ 709: appId({ signatures: Array.from({ length: 11 }, (_, i) => octet(new Uint8Array(32).fill(i))) }) }) }));
  await kdCase("app-package-3-elements", keyDescription({ sw: swList({ 709: appId({ packages: [seq(octet(enc(PACKAGE)), int(1), int(2))] }) }) }));
  await kdCase("app-package-1-element", keyDescription({ sw: swList({ 709: appId({ packages: [seq(octet(enc(PACKAGE)))] }) }) }));
  await kdCase("app-name-invalid-utf8", keyDescription({ sw: swList({ 709: appId({ packages: [seq(octet(Uint8Array.of(0xc3, 0x28)), int(1))] }) }) }));
  await kdCase("app-name-utf8string-type", keyDescription({ sw: swList({ 709: appId({ packages: [seq(utf8(PACKAGE), int(1))] }) }) }));
  await kdCase("app-version-octet", keyDescription({ sw: swList({ 709: appId({ packages: [seq(octet(enc(PACKAGE)), octet(Uint8Array.of(1)))] }) }) }));
  await kdCase("app-version-negative", keyDescription({ sw: swList({ 709: appId({ packages: [seq(octet(enc(PACKAGE)), int(-1))] }) }) }));
  await kdCase("app-signature-integer", keyDescription({ sw: swList({ 709: appId({ signatures: [int(4)] }) }) }));
  await kdCase("app-package-not-sequence", keyDescription({ sw: swList({ 709: appId({ packages: [octet(enc(PACKAGE))] }) }) }));
  await kdCase("app-trailing-byte-inside", keyDescription({ sw: swList({ 709: octet(concat(seq(set(seq(octet(enc(PACKAGE)), int(1))), set(octet(SIGNER))), Uint8Array.of(0))) }) }));
  await kdCase("app-inner-not-sequence", keyDescription({ sw: swList({ 709: octet(set(set(seq(octet(enc(PACKAGE)), int(1))), set(octet(SIGNER)))) }) }));
  await kdCase("app-inner-empty-octet", keyDescription({ sw: swList({ 709: octet(new Uint8Array()) }) }));
  await kdCase("app-duplicate-package", keyDescription({ sw: swList({ 709: appId({ packages: [seq(octet(enc(PACKAGE)), int(1)), seq(octet(enc(PACKAGE)), int(1))] }) }) }));
  await kdCase("app-same-package-two-versions", keyDescription({ sw: swList({ 709: appId({ packages: [seq(octet(enc(PACKAGE)), int(1)), seq(octet(enc(PACKAGE)), int(2))] }) }) }));
  await kdCase("app-duplicate-signature", keyDescription({ sw: swList({ 709: appId({ signatures: [octet(SIGNER), octet(SIGNER)] }) }) }));
  await kdCase("app-signer-31-bytes", keyDescription({ sw: swList({ 709: appId({ signatures: [octet(SIGNER.subarray(0, 31))] }) }) }));
  await kdCase("app-package-case", keyDescription({ sw: swList({ 709: appId({ packages: [seq(octet(enc(PACKAGE.toUpperCase())), int(1))] }) }) }));
  await kdCase("app-in-hw-and-sw", keyDescription({ hw: hwList({}, [ctx(709, appId())]) }));
  await kdCase("app-in-hw-only", keyDescription({ sw: swList({ 709: null }), hw: hwList({}, [ctx(709, appId())]) }));
  await kdCase("app-missing", keyDescription({ sw: swList({ 709: null }) }));
  await kdCase("app-empty-packages", keyDescription({ sw: swList({ 709: appId({ packages: [] }) }) }));

  // --- Certificate / chain structure ---
  await chainCase("cert-critical-attestation-ext", { kd: keyDescription(), leafExtensions: [attestationExt(keyDescription(), true)] });
  await chainCase("cert-no-leaf-extension", { leafExtensions: [] });
  await chainCase("cert-leaf-v1", { leafVersion: 1 });
  await chainCase("cert-leaf-two-extensions", { leafExtensions: [basicConstraintsExt, attestationExt(keyDescription())] });
  await chainCase("cert-leaf-duplicate-attestation-ext", { leafExtensions: [attestationExt(keyDescription()), attestationExt(keyDescription())] });
  await chainCase("cert-attestation-cert-has-ext", { attestationExtensions: [basicConstraintsExt, attestationExt(keyDescription())] });
  await chainCase("cert-attestation-cert-has-critical-ext", { attestationExtensions: [basicConstraintsExt, attestationExt(keyDescription(), true)] });
  await chainCase("cert-leaf-signed-by-intermediate", { leafSigner: keys.intermediate });
  await chainCase("cert-leaf-signed-by-root", { leafSigner: keys.root });
  await chainCase("cert-leaf-self-signed", { leafSigner: base.leafKey, leafKey: base.leafKey });
  await chainCase("cert-leaf-sigalg-mismatch", { leafOuterSigAlg: "1.2.840.10045.4.3.3" });
  await chainCase("cert-leaf-sigalg-sha384", { leafSigAlg: "1.2.840.10045.4.3.3" });
  await chainCase("cert-leaf-sigalg-unknown", { leafSigAlg: "1.2.840.10045.4.9.9" });
  await chainCase("cert-leaf-sigalg-rsa-with-ec-key", { leafSigAlg: "1.2.840.113549.1.1.11" });
  await chainCase("cert-leaf-issuer-mismatch", { leafIssuer: name(["cn", "other"]) });
  await chainCase("cert-leaf-issuer-case", { leafIssuer: name(["serialNumber", "DECAFBAD"]) });
  await chainCase("cert-leaf-issuer-utf8-type", { leafIssuer: name(["serialNumber", "decafbad", "utf8"]) });
  await chainCase("cert-leaf-issuer-trailing-space", { leafIssuer: name(["serialNumber", "decafbad "]) });
  await chainCase("cert-leaf-issuer-inner-spaces", { leafIssuer: name(["serialNumber", "decaf  bad"]), attestationSubject: name(["serialNumber", "decaf bad"]) });
  await chainCase("cert-leaf-issuer-cn-case", { attestationSubject: name(["cn", "Attest CA"], ["o", "Google LLC"]), leafIssuer: name(["cn", "attest ca"], ["o", "GOOGLE LLC"]) });
  await chainCase("cert-leaf-issuer-cn-spaces", { attestationSubject: name(["cn", "Attest CA"]), leafIssuer: name(["cn", "Attest   CA"]) });
  await chainCase("cert-leaf-issuer-cn-utf8-type", { attestationSubject: name(["cn", "Attest CA"]), leafIssuer: name(["cn", "Attest CA", "utf8"]) });
  await chainCase("cert-leaf-issuer-title-case", { attestationSubject: name(["serialNumber", "decafbad"], ["title", "TEE"]), leafIssuer: name(["serialNumber", "decafbad"], ["title", "tee"]) });
  await chainCase("cert-leaf-issuer-extra-rdn", { leafIssuer: name(["serialNumber", "decafbad"], ["cn", "x"]) });
  await chainCase("cert-leaf-expired", { leafNotAfter: NOW - DAY });
  await chainCase("cert-leaf-not-yet-valid", { leafNotBefore: NOW + DAY });
  await chainCase("cert-leaf-generalized-time", { });
  await chainCase("cert-attestation-expired-factory", { attestationNotAfter: NOW - DAY });
  await chainCase("cert-attestation-not-yet-valid", { attestationNotBefore: NOW + DAY });
  await chainCase("cert-intermediate-expired-factory", { intermediateNotAfter: NOW - DAY });
  await chainCase("cert-intermediate-expired-unknown-provisioning", { intermediateNotAfter: NOW - DAY, intermediateSubject: name(["cn", "Some CA"]), attestationSubject: name(["cn", "Attest"]) });
  await chainCase("cert-unknown-provisioning-4-certs", { intermediateSubject: name(["cn", "Some CA"]), attestationSubject: name(["cn", "Attest"]) });
  await chainCase("cert-remote-name-on-4-cert-chain", { intermediateSubject: name(["cn", "Droid CA2"], ["o", "Google LLC"]) });
  await chainCase("cert-remote-name-wrong-o", { intermediateSubject: name(["cn", "Droid CA2"], ["o", "Google"]) });
  await chainCase("cert-serialnumber-on-attestation-only", { intermediateSubject: name(["cn", "Some CA"]) });
  {
    const rsaRoot = await rsaKey();
    out.push(await toCase("cert-rsa-root", await buildChain({ rootKey: rsaRoot }, { root: rsaRoot, intermediate: keys.intermediate, attestation: keys.attestation })));
  }
  {
    const built = await buildChain({ leafKey: await ecKey("P-384") }, keys);
    out.push(await toCase("cert-leaf-key-p384", built, { pop: await sign(built.leafKey, CHALLENGE) }));
  }
  {
    const rsaLeaf = await rsaKey();
    const built = await buildChain({ leafKey: rsaLeaf }, keys);
    out.push(await toCase("cert-leaf-key-rsa", built, { pop: await sign(rsaLeaf, CHALLENGE) }));
  }
  {
    const otherRoot = await ecKey();
    out.push(await toCase("cert-untrusted-root", base, { roots: (await buildChain({ rootKey: otherRoot }, { root: otherRoot, intermediate: keys.intermediate, attestation: keys.attestation })).rootPem }));
    out.push(await toCase("cert-two-anchors-same-subject", base, { roots: (await buildChain({ rootKey: otherRoot }, { root: otherRoot, intermediate: keys.intermediate, attestation: keys.attestation })).rootPem + "\n" + base.rootPem }));
    out.push(await toCase("cert-two-anchors-same-subject-reversed", base, { roots: base.rootPem + "\n" + (await buildChain({ rootKey: otherRoot }, { root: otherRoot, intermediate: keys.intermediate, attestation: keys.attestation })).rootPem }));
    out.push(await toCase("cert-chain-without-root-two-anchors", base, { chain: base.chain.slice(0, -1), roots: (await buildChain({ rootKey: otherRoot }, { root: otherRoot, intermediate: keys.intermediate, attestation: keys.attestation })).rootPem + "\n" + base.rootPem }));
  }
  out.push(await toCase("chain-3-certs-root-attestation-leaf", base, { chain: [base.chain[0], base.chain[1], base.chain[3]] }));
  out.push(await toCase("chain-3-certs-unknown-provisioning", await buildChain({ intermediateSubject: name(["cn", "Some CA"]), attestationSubject: name(["cn", "Attest"]) }, keys), { chain: undefined }));
  {
    // 3-cert chain where the attestation cert is directly signed by the root (software-style shape).
    const att = await buildChain({ attestationSubject: name(["cn", "Attest"]) }, keys);
    out.push(await toCase("chain-3-certs-shape", att, { chain: [att.chain[0], att.chain[1], att.chain[3]] }));
  }
  out.push(await toCase("chain-6-certs", base, { chain: [...base.chain, base.chain[3], base.chain[3]] }));
  out.push(await toCase("chain-7-certs", base, { chain: [...base.chain, base.chain[3], base.chain[3], base.chain[3]] }));
  out.push(await toCase("chain-1-cert", base, { chain: [base.chain[0]] }));
  out.push(await toCase("chain-entry-5465-chars", base, { chain: [b64(base.chain[0]), "A".repeat(5465), b64(base.chain[2]), b64(base.chain[3])] }));
  out.push(await toCase("chain-entry-oversize-der", base, { chain: [b64(base.chain[0]), b64(new Uint8Array(4097).fill(0x30)), b64(base.chain[2]), b64(base.chain[3])] }));
  out.push(await toCase("chain-entry-oversize-valid-cert", base, { chain: [b64(base.chain[0]), b64(concat(base.chain[1], new Uint8Array(4096))), b64(base.chain[2]), b64(base.chain[3])] }));

  // --- Proof of possession ---
  {
    const rawSig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, base.leafKey.privateKey, CHALLENGE));
    out.push(await toCase("pop-p1363-format", base, { pop: rawSig }));
    const der = await pop(base.leafKey);
    out.push(await toCase("pop-trailing-byte", base, { pop: concat(der, Uint8Array.of(0)) }));
    out.push(await toCase("pop-truncated", base, { pop: der.subarray(0, der.length - 1) }));
    // non-minimal r encoding: insert a leading zero into r
    const inner = der.subarray(2);
    const rLen = inner[1];
    const r = inner.subarray(2, 2 + rLen);
    const rest = inner.subarray(2 + rLen);
    const nonMin = seq(tlv(0, false, 2, concat(Uint8Array.of(0), r)), rest);
    out.push(await toCase("pop-nonminimal-r", base, { pop: nonMin }));
    out.push(await toCase("pop-negative-s", base, { pop: seq(tlv(0, false, 2, r), tlv(0, false, 2, Uint8Array.of(0xff, 1))) }));
    out.push(await toCase("pop-zero-s", base, { pop: seq(tlv(0, false, 2, r), int(0)) }));
    out.push(await toCase("pop-extra-element", base, { pop: seq(tlv(0, false, 2, r), rest, int(0)) }));
    out.push(await toCase("pop-over-sha1-len-data", base, { pop: await sign(base.leafKey, CHALLENGE.subarray(0, 20)) }));
    out.push(await toCase("pop-other-key", base, { pop: await sign(await ecKey(), CHALLENGE) }));
    out.push(await toCase("pop-set-instead-of-seq", base, { pop: set(tlv(0, false, 2, r), rest) }));
  }

  // --- Challenge string forms (harness decodes the bytes; verifier compares against extension) ---
  out.push(await toCase("challenge-padded", base, { challenge: b64url(CHALLENGE) + "=" }));
  out.push(await toCase("challenge-std-alphabet", base, { challenge: b64(CHALLENGE) }));
  out.push(await toCase("challenge-empty", base, { challenge: "" }));

  // --- Revocation ---
  out.push(await toCase("rev-root-serial", base, { serials: ["ca11cafe"] }));
  out.push(await toCase("rev-root-serial-upper", base, { serials: ["CA11CAFE"] }));
  out.push(await toCase("rev-root-serial-leading-zeros", base, { serials: ["00ca11cafe"] }));
  out.push(await toCase("rev-leaf-serial", base, { serials: ["1"] }));
  out.push(await toCase("rev-leaf-serial-01", base, { serials: ["01"] }));
  out.push(await toCase("rev-attestation-serial", base, { serials: ["cafbad"] }));
  out.push(await toCase("rev-intermediate-serial", base, { serials: ["1234567890"] }));
  out.push(await toCase("rev-unrelated", base, { serials: ["deadbeef", "0"] }));

  // --- Config ---
  out.push(await toCase("cfg-wrong-package", base, { packageName: PACKAGE + ".debug" }));
  out.push(await toCase("cfg-wrong-signer", base, { signer: "00".repeat(32) }));
  out.push(await toCase("cfg-now-before-everything", base, { now: NOW - 30 * DAY }));
  out.push(await toCase("cfg-now-after-everything", base, { now: NOW + 30 * DAY }));
  out.push(await toCase("cfg-now-leaf-notafter-exact", base, { now: NOW + 7 * DAY }));
  out.push(await toCase("cfg-now-leaf-notafter-plus-1s", base, { now: NOW + 7 * DAY + 1000 }));
  out.push(await toCase("cfg-now-leaf-notbefore-exact", base, { now: NOW - 7 * DAY }));
  out.push(await toCase("cfg-now-leaf-notbefore-minus-1s", base, { now: NOW - 7 * DAY - 1000 }));
  return out;
}

/** Bit-flip and truncation mutations of one chain entry. */
export function byteMutations(id: string, c: Case, index: number, stride: number): Case[] {
  const der = Buffer.from(c.request.chain[index], "base64");
  const out: Case[] = [];
  const withChain = (suffix: string, bytes: Uint8Array) => {
    const chain = [...c.request.chain];
    chain[index] = Buffer.from(bytes).toString("base64");
    out.push({ ...c, id: `${id}-${suffix}`, request: { ...c.request, chain } });
  };
  for (let i = 0; i < der.length; i += stride) {
    const m = Uint8Array.from(der);
    m[i] ^= 1 << (i % 8);
    withChain(`flip${i}`, m);
  }
  for (let len = der.length - 1; len >= 0; len -= stride) withChain(`trunc${len}`, der.subarray(0, len));
  withChain("append0", concat(der, Uint8Array.of(0)));
  withChain("prepend0", concat(Uint8Array.of(0), der));
  return out;
}
