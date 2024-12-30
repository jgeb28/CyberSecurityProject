using System.Text;
using CybersecurityProject.Controllers;
using CybersecurityProject.Models;
using Microsoft.AspNetCore.Identity;
using OtpNet;
using static CybersecurityProject.Controllers.AccountController;
namespace CybersecurityProject.Services;

public class TotpService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly AesEncryptionService _aesEncryptionService;

    public TotpService(IHttpContextAccessor httpContextAccessor, AesEncryptionService aesEncryptionService)
    {
        _httpContextAccessor = httpContextAccessor;
        _aesEncryptionService = aesEncryptionService;
    }
    public string GenerateTotpSecret()
    {
        var password =_httpContextAccessor.HttpContext.Session.GetString("HashKey");
        if (password == null)
        {
            throw new InvalidOperationException("HashKey not found in session.");
        }
        
        var secret = KeyGeneration.GenerateRandomKey(16);
        
        string encryptedSecret = Convert.ToBase64String(_aesEncryptionService.EncryptKey(secret, password));
        Console.WriteLine($"Encrypted secret length (bytes): {encryptedSecret.Length}");
        var decodedBytes = Convert.FromBase64String(encryptedSecret);
        Console.WriteLine($"Decoded length: {decodedBytes.Length}");

        //_httpContextAccessor.HttpContext.Session.Remove("HashKey");
        return encryptedSecret;
    }
    
    public string RegenerateTotpSecret(string secret)
    {
        var password =_httpContextAccessor.HttpContext.Session.GetString("HashKey");
        if (password == null)
        {
            throw new InvalidOperationException("HashKey not found in session.");
        }
        
        string encryptedSecret = Convert.ToBase64String(_aesEncryptionService.EncryptKey(Base32Encoding.ToBytes(secret), password));
        //_httpContextAccessor.HttpContext.Session.Remove("HashKey");
        return encryptedSecret;
    }

    public async Task<bool> ValidateTotp(User user, UserManager<User> manager, string token)
    {
        var encryptedKey = await manager.GetAuthenticatorKeyAsync(user);
        var secret = await GetDecryptedAuthenticatorKeyAsync(user, encryptedKey);
        var secretKey = Base32Encoding.ToBytes(secret);
        var totp = new Totp(secretKey);
        _httpContextAccessor.HttpContext.Session.Remove("HashKey");
        return totp.VerifyTotp(token, out long timeStepMatched);
    }
    
    public async Task<string> GetDecryptedAuthenticatorKeyAsync(User user, string encryptedKey)
    {
        if (string.IsNullOrEmpty(encryptedKey))
        {
            throw new InvalidOperationException("Authenticator key not found.");
        }

        var password = _httpContextAccessor.HttpContext.Session.GetString("HashKey");
        if (_httpContextAccessor == null)
        {
            throw new InvalidOperationException("Pain.");
        }
        if (string.IsNullOrEmpty(password))
        {
            throw new InvalidOperationException("HashKey not found in session.");
        }

        string decryptedKey = Base32Encoding.ToString(_aesEncryptionService.DecryptKey(Convert.FromBase64String(encryptedKey), password));

        return decryptedKey;
    }
}