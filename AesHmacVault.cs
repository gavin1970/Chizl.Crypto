namespace Chizl.Crypto;

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

#nullable enable
/// <summary>
/// A composition-based approach where AES (typically in CBC or CTR mode) encrypts the plaintext, and an 
/// independent HMAC-SHA256 signature is calculated over the resulting ciphertext (and optionally an IV/salt). 
/// Decryption validates the MAC *before* decrypting the payload.
/// </summary>
public class AesHmacVault
{
    private const int SaltSize = 16;
    private const int IvSize = 16;
    private const int HmacSize = 32;       // SHA-256 HMAC tag length
    private const int Iterations = 600_000;
    private Exception? _lastError = null;


    /// <summary>
    /// Gets the last error that occurred during encryption or decryption.<br/>
    /// </summary>
    public Exception? LastError => _lastError;

    /// <summary>
    /// Simplier call that can be used by other languages like Python.<br/>
    /// Encrypts the given plaintext using AES-256 in CBC mode with HMAC-SHA256 for authentication.
    /// </summary>
    /// <param name="plainText">String to Encrypt</param>
    /// <param name="masterPassword">
    /// The passphrase used to derive cryptographic keys. 
    /// NOTE: This method does not mutate or clear the backing memory. 
    /// If using a mutable buffer (such as char[]), the caller is responsible 
    /// for zeroing the memory after use.
    /// </param>
    /// <returns>
    /// Base64 Encrypted string if successful.<br/>
    /// null if encryption failed and LastError holds it's exeception.
    /// </returns>
    public string? Encrypt(string plainText, string masterPassword)
    {
        if (!Encrypt(plainText, masterPassword.AsSpan(), out string? encryptedString))
            return null;

        return encryptedString;
    }

    /// <summary>
    /// Simplier call that can be used by other languages like Python.<br/>
    /// Decrypts a Base64 string using AES-256 in CBC mode with HMAC-SHA256 for authentication.
    /// </summary>
    /// <param name="base64Payload">Encrypted Base64 string to decrypt</param>
    /// <param name="masterPassword">
    /// The passphrase used to derive cryptographic keys. 
    /// NOTE: This method does not mutate or clear the backing memory. 
    /// If using a mutable buffer (such as char[]), the caller is responsible 
    /// for zeroing the memory after use.
    /// </param>
    /// <returns>
    /// UTF8 decrypted string if successful.<br/>
    /// null if decryption failed and LastError holds it's exeception.
    /// </returns>
    public string? Decrypt(string base64Payload, string masterPassword)
    {
        if (!Decrypt(base64Payload, masterPassword.AsSpan(), out string? decryptedString))
            return null;

        return decryptedString;
    }

    /// <summary>
    /// Encrypts the given plaintext using AES-256 in CBC mode with HMAC-SHA256 for authentication.
    /// </summary>
    /// <param name="plainText">String to Encrypt</param>
    /// <param name="masterPassword">
    /// The passphrase used to derive cryptographic keys. 
    /// NOTE: This method does not mutate or clear the backing memory. 
    /// If using a mutable buffer (such as char[]), the caller is responsible 
    /// for zeroing the memory via <see cref="CryptographicOperations.ZeroMemory"/> after use.
    /// </param>
    /// <param name="encryptedString">Base64 String of encrypted data</param>
    /// <returns>
    /// <see langword="true"/> when successfully encrypted.<br/>
    /// <see langword="false"/> if encryption failed and LastError holds it's exeception.
    /// </returns>
    public bool Encrypt(string plainText, ReadOnlySpan<char> masterPassword, out string? encryptedString)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] iv = RandomNumberGenerator.GetBytes(IvSize);
        _lastError = null;

        // Derive 64 bytes total: 32 bytes for AES key + 32 bytes for HMAC key
        byte[] derivedKeys = Rfc2898DeriveBytes.Pbkdf2(
            password: masterPassword,
            salt: salt,
            iterations: Iterations,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: 64
        );

        byte[] aesKey = derivedKeys[..32];
        byte[] hmacKey = derivedKeys[32..];

        try
        {
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = aesKey;
            aes.IV = iv;

            using MemoryStream ms = new();
            using (CryptoStream cs = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            using (StreamWriter writer = new(cs, Encoding.UTF8))
            {
                writer.Write(plainText);
            }
            byte[] cipherBytes = ms.ToArray();

            // Calculate HMAC over: Salt + IV + Ciphertext
            byte[] hmacTag;
            using (HMACSHA256 hmac = new(hmacKey))
            {
                hmac.TransformBlock(salt, 0, salt.Length, null, 0);
                hmac.TransformBlock(iv, 0, iv.Length, null, 0);
                hmac.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                hmacTag = hmac.Hash!;
            }

            // Pack: [Salt (16)] + [IV (16)] + [HMAC (32)] + [Ciphertext (N)]
            byte[] packed = new byte[SaltSize + IvSize + HmacSize + cipherBytes.Length];
            Buffer.BlockCopy(salt, 0, packed, 0, SaltSize);
            Buffer.BlockCopy(iv, 0, packed, SaltSize, IvSize);
            Buffer.BlockCopy(hmacTag, 0, packed, SaltSize + IvSize, HmacSize);
            Buffer.BlockCopy(cipherBytes, 0, packed, SaltSize + IvSize + HmacSize, cipherBytes.Length);

            encryptedString = Convert.ToBase64String(packed);
            return true;
        }
        catch(Exception ex)
        {
            _lastError = ex;
            encryptedString = null;
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
            CryptographicOperations.ZeroMemory(hmacKey);
            CryptographicOperations.ZeroMemory(derivedKeys);
        }
    }

    /// <summary>
    /// Decrypts a Base64 string using AES-256 in CBC mode with HMAC-SHA256 for authentication.
    /// </summary>
    /// <param name="base64Payload">Encrypted Base64 string to decrypt</param>
    /// <param name="masterPassword">
    /// The passphrase used to derive cryptographic keys. 
    /// NOTE: This method does not mutate or clear the backing memory. 
    /// If using a mutable buffer (such as char[]), the caller is responsible 
    /// for zeroing the memory via <see cref="CryptographicOperations.ZeroMemory"/> after use.
    /// </param>
    /// <param name="decryptedString">Decrypt string if successful. null if false was returned by method.</param>
    /// <returns>
    /// <see langword="true"/> when successfully decrypted.<br/>
    /// <see langword="false"/> if decrypted failed and LastError holds it's exeception.
    /// </returns>
    public bool Decrypt(string base64Payload, ReadOnlySpan<char> masterPassword, out string? decryptedString)
    {
        byte[] packed = Convert.FromBase64String(base64Payload);
        int minLength = SaltSize + IvSize + HmacSize;
        if (packed.Length < minLength)
        {
            _lastError = new CryptographicException("Payload too short.");
            decryptedString = null;
            return false;
        }
        else
            _lastError = null;

        // Unpack metadata
        byte[] salt = packed[..SaltSize];
        byte[] iv = packed[SaltSize..(SaltSize + IvSize)];
        byte[] storedHmac = packed[(SaltSize + IvSize)..minLength];
        byte[] cipherBytes = packed[minLength..];

        // Re-derive the exact same AES and HMAC keys
        byte[] derivedKeys = Rfc2898DeriveBytes.Pbkdf2(
            password: masterPassword,
            salt: salt,
            iterations: Iterations,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: 64
        );

        byte[] aesKey = derivedKeys[..32];
        byte[] hmacKey = derivedKeys[32..];

        try
        {
            // Verify HMAC signature FIRST (constant-time comparison)
            using (HMACSHA256 hmac = new(hmacKey))
            {
                hmac.TransformBlock(salt, 0, salt.Length, null, 0);
                hmac.TransformBlock(iv, 0, iv.Length, null, 0);
                hmac.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

                if (!CryptographicOperations.FixedTimeEquals(storedHmac, hmac.Hash))
                {
                    // Fails immediately if wrong password OR if file was tampered with
                    _lastError = new CryptographicException("Authentication failed: Wrong password or tampered data.");
                    decryptedString = null;
                    return false;
                }
            }

            // If HMAC passed, safe to decrypt with AES
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = aesKey;
            aes.IV = iv;

            using MemoryStream ms = new(cipherBytes);
            using CryptoStream cs = new(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using StreamReader reader = new(cs, Encoding.UTF8);

            decryptedString = reader.ReadToEnd();
            return true;
        }
        catch(Exception ex)
        {
            _lastError = ex;
            decryptedString = null;
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
            CryptographicOperations.ZeroMemory(hmacKey);
            CryptographicOperations.ZeroMemory(derivedKeys);
        }
    }
}