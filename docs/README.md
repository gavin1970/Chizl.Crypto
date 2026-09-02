# Chizl.Crypto

[![NuGet Version](https://img.shields.io/nuget/v/Chizl.Crypto.svg)](https://www.nuget.org/packages/Chizl.Crypto/)
[![License: MIT](https://img.shields.io/badge/license-MIT-orange.svg)](https://github.com/gavin1970/Chizl.Crypto/blob/master/LICENSE.md)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Chizl.Crypto)](https://www.nuget.org/packages/Chizl.Crypto/)<br/>
[![Target Frameworks](https://img.shields.io/badge/target%20frameworks-net8.0%20%7C%20net9.0%20%7C%20net10.0-purple)](https://dotnet.microsoft.com/)


https://www.nuget.org/packages/Chizl.Crypto

> This library provides production-grade implementations of two robust authenticated encryption paradigms: **AES-GCM** (Galois/Counter Mode) and **AES with HMAC-SHA256** (Encrypt-then-MAC).

## Symmetric Cryptography: AES-GCM vs. AES with HMAC-SHA256

Both primitives guarantee **confidentiality** (preventing unauthorized parties from reading the plaintext) and **authenticity / integrity** (detecting any tampering or ciphertext modification). However, they serve different operational environments and carry distinct failure modes.

--- 

## Project Includes
1. No dependencies on external libraries or NuGet packages; all cryptography is implemented using .NET's built-in `System.Security.Cryptography` namespace.
1. NUnit test coverage for both AES-GCM and AES with HMAC-SHA256 implementations, including edge cases and failure scenarios.  NUnit for this project is also setup to run by pressing F5 in Visual Studio, instead of having to run a separate test runner. [Test Results](NUnitTest.png)

---

## High Level Understanding

**AES-GCM (Galois/Counter Mode)**

* **Description:** An authenticated encryption with associated data (AEAD) cipher that combines Counter (CTR) mode encryption with a Galois field multiplication-based message authentication tag. It provides confidentiality and cryptographic integrity simultaneously in a single pass.
* **Best Used For:** High-throughput streaming, network protocols (like TLS 1.3), modern web APIs, and mobile applications where hardware acceleration (such as AES-NI or ARMv8 crypto extensions) is present.
* **Key Considerations:** Extremely fast on modern CPUs with native hardware support, but critically vulnerable to complete security collapse (catastrophic nonce reuse attack) if the initialization vector (IV/nonce) is ever repeated with the same key.

**AES with HMAC-SHA256 (Encrypt-then-MAC)**

* **Description:** A composition-based approach where AES (typically in CBC or CTR mode) encrypts the plaintext, and an independent HMAC-SHA256 signature is calculated over the resulting ciphertext (and optionally an IV/salt). Decryption validates the MAC *before* decrypting the payload.
* **Best Used For:** Systems requiring maximum defense-in-depth, legacy runtime environments lacking native GCM support, or long-term data at rest where accidental nonce repetition is a risk.
* **Key Considerations:** Immune to GCM's catastrophic failure modes under nonce collisions, but slower due to requiring two separate cryptographic passes. Requires careful key management—ideally deriving two distinct sub-keys (one for ciphering, one for hashing) via HKDF from a single master secret.

---

## Quick Comparison Matrix

| Feature | AES-GCM | AES + HMAC-SHA256 (EtM) |
| :--- | :--- | :--- |
| **Construction** | Native AEAD (CTR mode + GMAC) | Composition (AES-CBC or CTR + HMAC-SHA256) |
| **Processing Passes** | Single-pass (parallelizable) | Two-pass (Encrypt, then Hash) |
| **Performance** | High (hardware accelerated via AES-NI / PMULL) | Moderate (software-bound MAC evaluation) |
| **Key Management** | Single symmetric key (128, 192, or 256 bits) | **Two independent keys** (Cipher Key + Auth Key) |
| **Nonce/IV Vulnerability** | **Catastrophic** on reuse (leaks auth key & plaintext XOR) | Dependent on cipher mode; MAC remains tamper-proof |
| **Associated Data (AAD)** | Native built-in support | Supported (must be manually prepended into HMAC) |
| **Recommended Scope** | TLS, web APIs, streaming data, modern CPUs | Long-term cold storage, legacy runtimes, defense-in-depth |

---

## Detailed Guidance

### 1. AES-GCM (Galois/Counter Mode)

**Overview**

AES-GCM is an Authenticated Encryption with Associated Data (AEAD) algorithm standardized in NIST SP 800-38D. It pairs AES in Counter (CTR) mode with Galois Message Authentication Code (GMAC), calculating authentication tags using carry-less multiplication over GF(2¹²⁸).

**When to Use**

- **High-Throughput Services & APIs:** Network payloads, microservice RPCs, and real-time streaming where low latency and high I/O performance are required.
- **Hardware-Accelerated Environments:** Platforms equipped with x86 AES-NI/PCLMULQDQ or ARMv8 Crypto Extensions.
- **Modern Standards Compliance:** Systems aligning with TLS 1.3, WebCrypto, or modern envelope-encryption architectures.

**Security Gotchas & Nonce Limitations**

> [!CAUTION]
> **Zero Nonce Reuse Tolerance:** If a 96-bit nonce/IV is ever used twice with the same key, an adversary can recover the Galois hash sub-key ($H$) and forge authentication tags for any message, destroying both integrity and confidentiality.
> 
> If generating nonces purely at random (pseudo-randomly), NIST SP 800-38D limits a single key to **$2^{32}$ (approx. 4.29 billion) encryptions** due to the Birthday Paradox. If you risk exceeding this limit or cannot guarantee deterministic unique counters, rotate the key or use an extended-nonce construction (like AES-GCM-SIV or XChaCha20-Poly1305).

---

### 2. AES with HMAC-SHA256 (Encrypt-then-MAC)

**Overview**

This construction manually composes encryption and authentication following the **Encrypt-then-MAC (EtM)** paradigm, which has been mathematically proven to achieve ciphertext indistinguishability under adaptive chosen-ciphertext attacks (IND-CCA2). 

- The plaintext is encrypted with AES (e.g., in CBC or CTR mode) using $K_e$.
- An HMAC-SHA256 authentication tag is computed across the IV, the ciphertext, and optional AAD using a distinct key $K_m$.
- On decryption, the HMAC tag is verified in **constant time** before any decryption attempt is made, completely preventing padding oracle vulnerabilities.

**When to Use**

- **Defense-in-Depth & Cold Storage:** Data archiving and long-term storage where the risk of nonce collisions or implementation bugs in complex GCM polynomial arithmetic is unacceptable.
- **Constrained or Heterogeneous Runtimes:** Environments, embedded platforms, or legacy language runtimes without native, hardware-accelerated GCM implementations.
- **Resilience Against Nonce Misuse:** While reusing an IV in CBC mode reveals plaintext equality prefixes, it does not catastrophically leak the MAC key or permit arbitrary ciphertext tampering.

---

## Usage Examples (C#)

```csharp
using Chizl.Crypto;

string testString = "This is a test string to be encrypted.";
string pass = "P@$$w0rd";

// Instantiate the vault
var gcmEnc = new AesGcmVault();
// Encrypt the test string using the password, if successful, return the encrypted data; otherwise, throw an exception with the last error message.
if (gcmEnc.Encrypt(testString, pass.AsSpan(), out var encryptedData))
    return encryptedData;
else
    throw new Exception($"Encryption failed: {gcmEnc.LastError?.Message}");

// Instantiate the vault for decryption
var gcmDec = new AesGcmVault();
// Decrypt the encrypted data using the password, if successful, return the decrypted data; otherwise, throw an exception with the last error message.
if (gcmDec.Decrypt(encryptedData, pass.AsSpan(), out var decryptedData))
    return decryptedData; 
else
    throw new Exception($"Decryption failed: {gcmDec.LastError?.Message}");
```

--- 

## Usage Examples (Python)

> pip install pythonnet

### Example A: AES-256-GCM

```python
import os
import clr
from pythonnet import load

# Initialize .NET Core runtime (loads your local .NET 8 runtime)
load("coreclr")
# Add reference to your compiled DLL
clr.AddReference(os.path.abspath("Chizl.Crypto.dll"))

# Import both classes by namespace for AesGcmVault and AesHmacVault
# from Chizl.Crypto import AesGcmVault, AesHmacVault

# Import a single class by namespace for AesGcmVault
from Chizl.Crypto import AesGcmVault

# Instantiate the vault
vault = AesGcmVault()
password = "SuperSecurePassword123!"

# In pythonnet, 'out' parameters are returned as a tuple: (result, out_param1, ...)
# The Signature for bool return has a required second parameter that isn't supported by Python
# bool Encrypt(string, ReadOnlySpan<char>, out string)
# --------------
# In this example we use the a more simple approach and the return
# the value as an encrypted string or null if an error occurs.  
# LastError is cleared on entry then set if a failure occurs.
encrypted = vault.Encrypt("Top-secret payload from Python", password)

if encrypted is not None:
    print(f"Encrypted: {encrypted}")

    # Decrypt the payload
    decrypted = vault.Decrypt(encrypted, password)
    
    if decrypted is not None:
        print(f"Decrypted: {decrypted}")
    else:
        print(f"Decryption failed: {vault.LastError.Message}")
else:
    print(f"Encryption failed: {vault.LastError.Message}")
```

