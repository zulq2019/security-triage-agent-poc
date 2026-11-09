# Intake fixtures (SYNTHETIC)

Every file here is synthetic test data. Component names, advisory ids (`CVE-2099-*`, `BDSA-2099-*`), URLs, repos and SHAs are invented;
the shapes follow public Black Duck sample reports / the public Detect source so the parsers can be exercised before a real sample arrives.

| File | Shape it imitates |
| --- | --- |
| `blackduck-sca.sarif.json` | Black Duck SCA SARIF from the Black Duck Security Scan action (Bridge CLI), grouped by component, plus a Polaris-style SAST rule, a generic result with explicit properties, a licence result, a suppressed result and an instruction-like message |
| `secret.sarif.json` | gitleaks-style SARIF whose `region.snippet` carries a secret (the AWS documentation example key) |
| `blackduck-rapid.json` | Detect rapid / stateless scan `*_BlackDuck_DeveloperMode_Result.json` (gson of `List<DeveloperScansScanView>`) |
| `blackduck-components-with-locations.json` | Detect component location analysis output (`componentList`) |
