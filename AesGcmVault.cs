namespace Chizl.Crypto;

using System;
using System.Security.Cryptography;
using System.Text;

#nullable enable
/// <summary>
/// An authenticated encryption with associated data (AEAD) cipher that combines Counter (CTR) 
/// mode encryption with a Galois field multiplication-based message authentication tag. It 
/// provides confidentiality and cryptographic integrity simultaneously in a single pass.
/// </summary>
public class AesGcmVault
{
    private const int SaltSize = 16;        // 128-bit Salt for PBKDF2
    private const int NonceSize = 12;       // 96-bit Nonce standard for AES-GCM
    private const int TagSize = 16;         // 128-bit Authentication Tag
    private const int KeySize = 32;         // 256-bit AES Key
    private const int Iterations = 600_000; // PBKDF2 work factor
    private Exception? _lastError = null;

    /// <summary>
    /// Gets the last error that occurred during encryption or decryption.<br/>
    /// </summary>
    public Exception? LastError => _lastError;

    /// <summary>
    /// Simplier call to be called by Python.<br/>
    /// Uses the same Encrypt method but converts the string masterPassword to a ReadOnlySpan--char>-
    /// and returns null instead a false if LastError should be looked at.<br/>
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
    /// null  if encryption failed and LastError holds it's exeception.
    /// </returns>
    public string? Encrypt(string plainText, string masterPassword)
    {
        if (!Encrypt(plainText, masterPassword.AsSpan(), out string? encryptedString))
            return null;

        return encryptedString;
    }

    /// <summary>
    /// Simplier call that can be used by other languages like Python.<br/>
    /// Decrypts a Base64 string that was encrypted with AES-GCM and a password-derived key.<br/>
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
    /// Encrypts a string using AES-GCM with a password-derived key.<br/>
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
        int plainByteCount = Encoding.UTF8.GetByteCount(plainText);
        int totalSize = SaltSize + NonceSize + TagSize + plainByteCount;
        _lastError = null;

        // Allocate the output container once
        byte[] packed = new byte[totalSize];
        Span<byte> packedSpan = packed.AsSpan();

        // Slice contiguous regions for each segment
        Span<byte> salt = packedSpan.Slice(0, SaltSize);
        Span<byte> nonce = packedSpan.Slice(SaltSize, NonceSize);
        Span<byte> tag = packedSpan.Slice(SaltSize + NonceSize, TagSize);
        Span<byte> cipherBytes = packedSpan.Slice(SaltSize + NonceSize + TagSize, plainByteCount);

        RandomNumberGenerator.Fill(salt);
        RandomNumberGenerator.Fill(nonce);

        Span<byte> plainBytes = stackalloc byte[plainByteCount <= 256 ? plainByteCount : 0];
        byte[]? rented = plainByteCount > 256 ? new byte[plainByteCount] : null;
        Span<byte> effectivePlain = rented ?? plainBytes;

        Span<byte> key = stackalloc byte[KeySize];

        try
        {
            Encoding.UTF8.GetBytes(plainText, effectivePlain);

            Rfc2898DeriveBytes.Pbkdf2(
                masterPassword,
                salt,
                key,
                Iterations,
                HashAlgorithmName.SHA256
            );

            using (AesGcm aesGcm = new(key, TagSize))
            {
                // Writes ciphertext directly into the output array slice
                aesGcm.Encrypt(nonce, effectivePlain, cipherBytes, tag);
            }

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
            CryptographicOperations.ZeroMemory(cipherBytes);
            CryptographicOperations.ZeroMemory(plainBytes);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(effectivePlain);
        }
    }

    /// <summary>
    /// Decrypts a Base64 string that was encrypted with AES-GCM and a password-derived key.<br/>
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
        ReadOnlySpan<byte> packedSpan = packed.AsSpan();
        _lastError = null;

        int headerSize = SaltSize + NonceSize + TagSize;

        if (packedSpan.Length < headerSize)
        {
            _lastError = new CryptographicException("Corrupt payload: Data stream is too short.");
            decryptedString = null;
            return false;
        }

        // Unpack header slices
        ReadOnlySpan<byte> salt = packedSpan.Slice(0, SaltSize);
        ReadOnlySpan<byte> nonce = packedSpan.Slice(SaltSize, NonceSize);
        ReadOnlySpan<byte> tag = packedSpan.Slice(SaltSize + NonceSize, TagSize);
        ReadOnlySpan<byte> cipherBytes = packedSpan.Slice(headerSize);

        // Re-derive the key
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            password: masterPassword,
            salt: salt,
            iterations: Iterations,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: KeySize
        );

        byte[] plainBytes = new byte[cipherBytes.Length];

        try
        {
            // Decrypt and verify tag in one native pass
            using (AesGcm aesGcm = new(key, TagSize))
            {
                // If tag does not match (wrong password or modified ciphertext),
                // this throws CryptographicException immediately.
                aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);
            }

            decryptedString = Encoding.UTF8.GetString(plainBytes);
            return true;
        }
        catch (CryptographicException e)
        {
            _lastError = e;
            decryptedString = null;
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }
}