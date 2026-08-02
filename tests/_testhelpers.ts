/**
 * Shared test helpers for the devtools test suite.
 *
 * Kept out of the `*.test.ts` glob so vitest does not try to run it as a test file.
 */

/**
 * A minimal but valid PEM-encoded X.509 certificate (v1, self-signed, CN=Helper).
 * Generated once for import so CLI/inspect tests have a stable cert to read.
 */
export function makeMinimalCert(): string {
    // DER bytes of a tiny valid certificate, base64-wrapped in PEM armor.
    const b64 =
        "MIIC6DCCAdACCQCrGrse2wrmWDANBgkqhkiG9w0BAQsFADA2MRUwEwYDVQQDDAxU" +
        "ZXN0IEV4YW1wbGUxEDAOBgNVBAoMB1Rlc3RPcmcxCzAJBgNVBAYTAlVTMB4XDTI2" +
        "MDgwMjExMzQwNloXDTM2MDczMDExMzQwNlowNjEVMBMGA1UEAwwMVGVzdCBFeGFt" +
        "cGxlMRAwDgYDVQQKDAdUZXN0T3JnMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcN" +
        "AQEBBQADggEPADCCAQoCggEBANfp/xLC5ZPXIM8n60eGcC0FEsmBJfyxO0m3DFNx" +
        "Wg2EuUJ1Ma4JlWEEKnDAfeBAw1+pnbQpACIajxV3vPB9nEyGGfryExuwpwlhH3nQ" +
        "nFe9+o1EmZNHIKsHH1Zxezc824Vt0cRW5djKnJYHFxnP4RvcVJEf4uEXbrC+wuNN" +
        "463hmavnsdrxPd9olAhinE6iOAX5zAa1W3b0xP0OnKU5DhCGDrQ92Cz42GCCnUjf" +
        "/thAU4NLVl580f9iu16LQv8VAp0wTCBTDRz26ai79RAinvg4Fz2qTTxdt2yLOoei" +
        "fiLZe3YRKFAP2EgLTCNYUtIbrqinZ5B2mZXvJxXXUaDunqkCAwEAATANBgkqhkiG" +
        "9w0BAQsFAAOCAQEAKYGbFbgerKl+xkd/cQY6eC86DYVC56ghyJ9LgfkepV1K9H2L" +
        "yjC5TRMHu2C3LJB6Q3S/8paqh5iaT+wQUKxD9sBO2STsEAhNhH6S/WTf7BbCUhmz" +
        "5HjJ8MMkf0TvRUYe1LHHvIuAwp7RWaKm1R/c8zx07dvGX5Vj/+N5O+m4t14hGrCC" +
        "6rFPX0yvVIRucmfgVwezdZRa/1wwUaW8ft0Zcgk79C1HLdn2oYjlDh3EYmj/B0ul" +
        "QGbtZchxlogEy7W/v22cNypLlaRRkOYoXkC77I5+yCShVfqEPqCTrzMu7zi0EtdM" +
        "ezen4FLFuPGLzooovE/t9eIesAKmu47vWNxpZA==";
    const lines = b64.match(/.{1,64}/g) ?? [];
    return ["-----BEGIN CERTIFICATE-----", ...lines, "-----END CERTIFICATE-----"].join("\n");
}
