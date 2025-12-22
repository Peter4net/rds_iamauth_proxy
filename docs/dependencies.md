# Dependency Notes

## Current Versions (December 2025)

| Component | Version | Notes |
|-----------|---------|-------|
| Rust (muslrust) | 1.85.0-stable | Rust 2024 edition support |
| Alpine | 3.21 | Supported until Nov 2026 |
| AWS SDK | 1.0.3 | Pinned due to MSRV constraints |
| Tokio | 1.48 | LTS until Sep 2026 |

## AWS SDK Constraints

The AWS SDK crates are pinned to exact versions (`=1.0.3`) because:

1. **MSRV Requirements**: The latest AWS SDK for Rust (1.8.x) requires **Rust 1.88** as its minimum supported Rust version (MSRV)
2. **muslrust Limitations**: As of December 2025, muslrust images 1.89+ have OpenSSL configuration issues for musl cross-compilation
3. **Version Coupling**: AWS SDK crates (aws-config, aws-credential-types, aws-sigv4, aws-smithy-*) are tightly coupled and must be upgraded together

### Affected Crates

```toml
aws-config = "=1.0.3"
aws-credential-types = "=1.0.3"
aws-sigv4 = "=1.0.3"
```

## Future Upgrade Path

To upgrade the AWS SDK to the latest version:

1. Wait for a muslrust release (1.88+) with working OpenSSL/musl support
2. Update `Dockerfile` to use the new muslrust version
3. Remove the exact version pins (`=`) from AWS crates in `Cargo.toml`
4. Test the build thoroughly

### Checking for Updates

```bash
# Check latest muslrust tags
docker pull clux/muslrust:stable
docker run --rm clux/muslrust:stable rustc --version

# Check AWS SDK MSRV
# Visit: https://github.com/awslabs/aws-sdk-rust
# The SDK follows a "stable-2" MSRV policy (current stable minus 2 versions)
```

## Alpine Linux

Alpine 3.18.x reached end-of-life in May 2025. The project now uses Alpine 3.21.

| Version | EOL Date |
|---------|----------|
| 3.21 | Nov 2026 |
| 3.20 | Apr 2026 |
| 3.19 | Nov 2025 (EOL) |
| 3.18 | May 2025 (EOL) |

## Tokio

Using Tokio 1.48 which is part of the LTS release series (supported until September 2026). The MSRV for Tokio is 1.70.
