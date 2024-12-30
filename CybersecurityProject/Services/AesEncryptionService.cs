using System.Security.Cryptography;

namespace CybersecurityProject.Services;

public class AesEncryptionService
{
    public byte[] EncryptKey(byte[] key, string password)
    {
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(iv);
        }
        
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10_000, HashAlgorithmName.SHA256);
        byte[] aesKey = pbkdf2.GetBytes(32);
        using var fileStream = new MemoryStream();
        using Aes aes = Aes.Create();
        using CryptoStream cryptStream = new CryptoStream(
            fileStream, aes.CreateEncryptor(aesKey, iv), CryptoStreamMode.Write);
        cryptStream.Write(key, 0, key.Length); 
        cryptStream.FlushFinalBlock();
        
        byte[] ciphertext = fileStream.ToArray();
        byte[] encryptedData = new byte[salt.Length + iv.Length + ciphertext.Length];
        Buffer.BlockCopy(salt, 0, encryptedData, 0, salt.Length);
        Buffer.BlockCopy(iv, 0, encryptedData, salt.Length, iv.Length);
        Buffer.BlockCopy(ciphertext, 0, encryptedData, salt.Length + iv.Length, ciphertext.Length);

        return encryptedData;
    }
    
    public byte[] DecryptKey(byte[] cipher, string password)
    {
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[cipher.Length - salt.Length - iv.Length];
       
        Buffer.BlockCopy(cipher, 0, salt, 0, salt.Length);
        Buffer.BlockCopy(cipher, salt.Length, iv, 0, iv.Length);
        Buffer.BlockCopy(cipher, salt.Length + iv.Length, ciphertext, 0, ciphertext.Length);
        
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10_000, HashAlgorithmName.SHA256);
        byte[] aesKey = pbkdf2.GetBytes(32);
        
        var fileStream = new MemoryStream(ciphertext);
        using Aes aes = Aes.Create();
        using CryptoStream cryptStream = new CryptoStream(
            fileStream, aes.CreateDecryptor(aesKey, iv), CryptoStreamMode.Read);
        using var decryptedData = new MemoryStream();
        cryptStream.CopyTo(decryptedData);
    
        return decryptedData.ToArray();
    }
}