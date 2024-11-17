# Aigis

> [!NOTE]
> 本元服务已正式上架应用市场，请搜索“Aigis”使用！

A lightweight alternative to [Aegis Authenticator](https://github.com/beemdevelopment/Aegis) for HarmonyOS NEXT, with pure ArkTS implementation and no 3rd party dependencies.

<p float="left">
  <img height="500px" alt="screenshot_light" src="./docs/images/screenshot_light.jpg" />
  &nbsp;&nbsp;&nbsp;&nbsp;
  <img height="500px" alt="screenshot_dark" src="./docs/images/screenshot_dark.jpg" />
</p>

### Security Design (for version `>=1.0.0`)

```mermaid
flowchart LR

Dst1[["OTP Tokens"]]
Dst2[("Items & Settings")]
Dst3[("Aigis Exports")]

Src0(["Biometric/PIN (ATL1)"])

Src1(["Biometric (ATL3)"])

Src2(["Password"])
Src2a["dec_master_key"]
Via2[("Encrypted Secrets<br/>(AES256-GCM)")]
Src2b["enc_master_key"]

subgraph "User Input"
Src0
Src1
Src2
end

subgraph "HUKS (TEE)"
Src2a
Src2b
end

subgraph "APP Sandbox"
Via2
Dst2
end

subgraph "Output"
Dst1
Dst3
end

Src1--Authenticate-->Src2a
Src2--PBKDF2/AES256-->Src2a--decrypt-->Via2-->Dst1
Src2--PBKDF2/AES256-->Src2b--encrypt-->Via2

Src0--"Authenticate"-->Dst2

Via2-->Dst3
Dst2-->Dst3
```

**Fallback Security Design**: If ATL3 is invalidated for any reason, the password will be prompted to decrypt the "Encrypted Secrets", and then re-import `dec_master_key` with no auth. If ATL1 is invalidated for any reason, the APP will be inaccessible until reinstalled.

### Roadmap

**Release v0.3.0** (2024/11/18)

- [ ] Change Password Procedure Design
  - Change password dialog
  - Decrypt and then re-encrypt the secrets
  - Re-import the `enc_master_key` and `dec_master_key`

**Release v0.5.0** (2024/11/22)

- [ ] Some UX Improvement
  - Better Setting Item Descriptions
  - URI Parse Support Multi-line (`otpauth` only)
  - Support Notes Add & Display on Edit Page
  - URI & QR Code Display on Edit Page (Auth Required)
  - "Move-to-Top" --> "Favorite Items"
- [ ] Item Sorting "Custom / Alphabetic / Usage Count"
- [ ] Support Drag Item to Sort (#16)
- [ ] Password Challenge Page Design
  - Periodic Notification in the Local Non-Working Hours
  - Also allow to skip the challenge

**Release v1.0.0** (2024/11/29)

- [ ] Support started with `otpauth://` link Want Param
- [ ] Support `otpauth-migration://` link
  - via Handwritten ProtoBuf Decode
- [ ] [Aegis](https://github.com/beemdevelopment/Aegis) format vault import & export
  - `scrypt` Implementation based on PBKDF2


### References

- [Aegis Authenticator - ctypto/otp](https://github.com/beemdevelopment/Aegis/tree/master/app/src/main/java/com/beemdevelopment/aegis/crypto/otp)

- [Github - pyotp](https://github.com/pyauth/pyotp.git)

- HarmonyOS NEXT 官方文档
  
  - [文档中心 - 元服务开发指南](https://developer.huawei.com/consumer/cn/doc/atomic-guides-V5/atomic-service-V5)

  - [文档中心 - 设计指南](https://developer.huawei.com/consumer/cn/doc/design-guides/design-concepts-0000001795698445)

  - [文档中心 - 开发指南](https://developer.huawei.com/consumer/cn/doc/harmonyos-guides-V5/application-dev-guide-V5?catalogVersion=V5)

  - [文档中心 - API参考](https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/development-intro-api-V5?catalogVersion=V5)
