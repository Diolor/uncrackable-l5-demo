# Google attestation roots

`google-attestation-roots.pem` is the PEM bundle of Google's published hardware
attestation root certificates, retrieved on 2026-09-09 from
<https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate>.
The RSA root that expired on 2026-05-24 is omitted. The file contains only
certificate blocks so it can be stored verbatim as the `ATTESTATION_ROOTS` secret.

Before trusting this bundle anywhere, compare each SHA-256 certificate fingerprint
against Google's page. PEM validation alone does not establish provenance.

| Subject | SHA-256 fingerprint | Expires |
| --- | --- | --- |
| `serialNumber=f92009e853b6b045` | `CE:DB:1C:B6:DC:89:6A:E5:EC:79:73:48:BC:E9:28:67:53:C2:B3:8E:E7:1C:E0:FB:E3:4A:9A:12:48:80:0D:FC` | Mar 15 18:07:48 2042 GMT |
| `CN=Key Attestation CA1, OU=Android, O=Google LLC, C=US` | `6D:9D:B4:CE:6C:5C:0B:29:31:66:D0:89:86:E0:57:74:A8:77:6C:EB:52:5D:9E:43:29:52:0D:E1:2B:A4:BC:C0` | Jul 15 22:32:18 2035 GMT |
| `serialNumber=f92009e853b6b045` | `1E:F1:A0:4B:8B:A5:8A:B9:45:89:AC:49:8C:89:82:A7:83:F2:4E:A7:30:7E:01:59:A0:C3:A7:3B:37:7D:87:CC` | Nov 18 20:37:58 2034 GMT |
| `serialNumber=f92009e853b6b045` | `AB:66:41:17:8A:36:E1:79:AA:0C:1C:DD:DF:9A:16:EB:45:FA:20:94:3E:2B:8C:D7:C7:C0:5C:26:CF:8B:48:7A` | Nov 13 23:10:42 2036 GMT |
