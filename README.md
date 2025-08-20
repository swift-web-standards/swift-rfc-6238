# swift-rfc-6238

Swift implementation of [RFC 6238: TOTP: Time-Based One-Time Password Algorithm](https://www.rfc-editor.org/rfc/rfc6238.html) and [RFC 4226: HOTP: HMAC-Based One-Time Password Algorithm](https://www.rfc-editor.org/rfc/rfc4226.html)

## Overview

This package provides a **pure RFC-compliant implementation** of TOTP and HOTP algorithms without any cryptographic dependencies, making it lightweight, flexible, and universally compatible across all Swift platforms.

## Features

- ✅ **RFC 6238 & RFC 4226 Compliant**: Full implementation of TOTP and HOTP specifications
- 🪶 **Zero Dependencies**: Pure Swift implementation with no crypto dependencies
- 🌐 **Cross-Platform**: Works on all Swift platforms (Linux, Windows, macOS, iOS, etc.)
- 🔧 **Flexible**: Protocol-based HMAC provider supports any cryptographic backend
- ⚡ **Type-Safe**: Throwing initializers for proper error handling
- 🧪 **Testable**: Easy to mock HMAC providers for testing
- 📦 **Modular**: Choose your crypto implementation separately

## Installation

### Swift Package Manager

Add this to your Package.swift:

```swift
dependencies: [
    .package(url: "https://github.com/swift-web-standards/swift-rfc-6238.git", from: "0.0.1")
]
```

## Quick Start

### Basic Usage with Custom HMAC Provider

```swift
import RFC_6238

// Define your HMAC provider
struct MyHMACProvider: RFC_6238.HMACProvider {
    func hmac(algorithm: RFC_6238.Algorithm, key: Data, data: Data) -> Data {
        // Use your preferred crypto library
        switch algorithm {
        case .sha1:
            return HMAC<SHA1>.authenticationCode(for: data, using: key)
        case .sha256:
            return HMAC<SHA256>.authenticationCode(for: data, using: key)
        case .sha512:
            return HMAC<SHA512>.authenticationCode(for: data, using: key)
        }
    }
}

// Create TOTP instance
let totp = try RFC_6238.TOTP(
    base32Secret: "JBSWY3DPEHPK3PXP",
    timeStep: 30,
    digits: 6,
    algorithm: .sha1
)

// Generate OTP
let hmacProvider = MyHMACProvider()
let otp = totp.generate(using: hmacProvider)
print("Current OTP: \(otp)")

// Validate OTP
let isValid = totp.validate("123456", using: hmacProvider)
print("OTP is valid: \(isValid)")
```

### HOTP Usage

```swift
import RFC_6238

// Create HOTP instance
let hotp = try RFC_6238.HOTP(
    secret: secretData,
    digits: 6,
    algorithm: .sha256
)

// Generate OTP for counter value
let otp = hotp.generate(counter: 42, using: hmacProvider)
```

### Provisioning URI for Authenticator Apps

```swift
// Generate QR code data for Google Authenticator, Authy, etc.
let uri = totp.provisioningURI(
    label: "user@example.com",
    issuer: "Example Corp"
)
// Output: otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30&issuer=Example%20Corp
```

### Time-Based Features

```swift
// Check remaining time until next OTP
let secondsRemaining = totp.timeRemaining()
print("Next OTP in: \(secondsRemaining) seconds")

// Generate OTP for specific time
let pastDate = Date(timeIntervalSinceNow: -60)
let pastOTP = totp.generate(at: pastDate, using: hmacProvider)

// Validate with time window (allows ±1 time step by default)
let isValidWithWindow = totp.validate(otp, window: 2, using: hmacProvider)
```

## Architecture

### Protocol-Based Design

The package uses a protocol-based approach for HMAC operations, allowing you to plug in any cryptographic library:

```swift
public protocol HMACProvider {
    func hmac(algorithm: Algorithm, key: Data, data: Data) -> Data
}
```

This design enables:
- **Flexibility**: Use CryptoKit on Apple platforms, OpenSSL on Linux, or any other crypto library
- **Testability**: Easily mock HMAC operations in tests
- **No Lock-in**: Switch crypto providers without changing your code
- **Minimal Dependencies**: Core package has zero dependencies

### Error Handling

All initialization methods use throwing initializers for safe error handling:

```swift
public enum Error: Swift.Error, LocalizedError {
    case invalidBase32String
    case invalidDigits(String)
    case invalidTimeStep(String) 
    case emptySecret
}
```

## Supported Features

### TOTP (RFC 6238)
- ✅ Time-based OTP generation
- ✅ Configurable time step (default: 30 seconds)
- ✅ Variable digit length (6-8 digits)
- ✅ Multiple hash algorithms (SHA1, SHA256, SHA512)
- ✅ Time window validation
- ✅ Provisioning URI generation
- ✅ Time remaining calculation

### HOTP (RFC 4226)
- ✅ Counter-based OTP generation
- ✅ Dynamic truncation
- ✅ Variable digit length (6-8 digits)
- ✅ Multiple hash algorithms

### Security Features
- ✅ Constant-time comparison to prevent timing attacks
- ✅ Proper error handling with throwing initializers
- ✅ Base32 encoding/decoding (RFC 4648)
- ✅ No hardcoded secrets or keys

## Testing

```swift
import Testing
@testable import RFC_6238

// Mock HMAC provider for testing
struct MockHMACProvider: RFC_6238.HMACProvider {
    let expectedResult: Data
    
    func hmac(algorithm: RFC_6238.Algorithm, key: Data, data: Data) -> Data {
        return expectedResult
    }
}

@Test func testTOTPGeneration() throws {
    let totp = try RFC_6238.TOTP(
        secret: Data("secret".utf8),
        digits: 6
    )
    
    let mockProvider = MockHMACProvider(
        expectedResult: Data(repeating: 0x42, count: 20)
    )
    
    let otp = totp.generate(using: mockProvider)
    #expect(otp.count == 6)
}
```

## Use Cases

This package is perfect for:

- 🔐 **Two-Factor Authentication**: Implement 2FA in your applications
- 🧪 **Testing**: Mock OTP generation for unit tests
- 🏗️ **Custom Crypto**: Integrate with specialized cryptographic libraries
- 📱 **Cross-Platform**: Deploy OTP functionality on any Swift platform
- 🪶 **Minimal Dependencies**: Keep your dependency graph clean

## Documentation

- **[RFC 6238 Specification](https://www.rfc-editor.org/rfc/rfc6238.html)**: TOTP Algorithm
- **[RFC 4226 Specification](https://www.rfc-editor.org/rfc/rfc4226.html)**: HOTP Algorithm
- **[RFC 4648 Section 5](https://www.rfc-editor.org/rfc/rfc4648.html#section-5)**: Base32 Encoding

## License

This project is licensed under the MIT License - see the LICENSE file for details.