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
        
        string encryptedSecret = Base32Encoding.ToString(_aesEncryptionService.EncryptKey(secret, password));
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
        Console.WriteLine();
        Console.WriteLine(secret);
        byte[] secretBytes = Base32Encoding.ToBytes(secret);
        Console.WriteLine(secretBytes.Length);
        string encryptedSecret = Base32Encoding.ToString(_aesEncryptionService.EncryptKey(secretBytes, password));
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

        var secretbytes = Base32Encoding.ToBytes(encryptedKey);
        var secret = _aesEncryptionService.DecryptKey(secretbytes, password);
        Console.WriteLine(secret);
        string decryptedKey = Base32Encoding.ToString(secret);
        Console.WriteLine("decryptedKey");
        Console.WriteLine(decryptedKey);
        
        return decryptedKey;
    }
}