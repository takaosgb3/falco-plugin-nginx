# Binary Distribution Guidelines

This document explains the licensing and distribution model for the Falco nginx plugin binaries.

## Distribution Model

This repository follows a **binary-only distribution model**:

- **What we provide**: Pre-compiled binaries, documentation, and configuration files
- **What we don't provide**: Source code (maintained in a separate private repository)
- **Why this model**: Simplifies deployment while maintaining code security

## Licensing

### Our License

The Falco nginx plugin binaries are distributed under the **Apache License 2.0**.

This means you can:
- ✅ Use the binaries in production
- ✅ Distribute the binaries
- ✅ Include in commercial products
- ✅ Modify configuration files and rules

### Third-Party Components

Our binaries include code from these open-source projects:

| Component | License | Usage |
|-----------|---------|-------|
| Falco Plugin SDK for Go | Apache 2.0 | Core plugin framework |
| Go standard library | BSD-style | Runtime and utilities |
| fsnotify | BSD-3-Clause | File monitoring |
| encoding/gob | BSD-style | Event serialization |

### Your Obligations

When distributing our binaries:

1. **Include our LICENSE file**
2. **Include our NOTICE file** (for attribution)
3. **Don't claim authorship** of the binaries
4. **Preserve copyright notices**

## Best Practices for Binary Distribution

### 1. Security Verification

Always verify binary integrity:

```bash
# Download SHA256 checksum
curl -O https://github.com/takaosgb3/falco-plugin-nginx/raw/main/releases/libfalco-nginx-plugin-linux-amd64.so.sha256

# Verify binary
sha256sum -c libfalco-nginx-plugin-linux-amd64.so.sha256
```

### 2. Version Management

- Pin to specific versions in production
- Test updates in staging first
- Keep SHA256 checksums for audit trails

### 3. Documentation

When using our binaries:
- Link back to this repository
- Document which version you're using
- Include our troubleshooting guide

## FAQ

**Q: Can I use these binaries in commercial products?**
A: Yes, the Apache 2.0 license allows commercial use.

**Q: Do I need to open-source my Falco rules?**
A: No, your custom rules remain your property.

**Q: Can I request custom builds?**
A: Contact the maintainers for special requirements.

**Q: Why not open source?**
A: We maintain source code privately for security and quality control while providing free binaries for community use.

## Support

- **Issues**: [GitHub Issues](https://github.com/takaosgb3/falco-plugin-nginx/issues)
- **Security**: Report vulnerabilities privately to maintainers
- **Updates**: Watch this repository for new releases