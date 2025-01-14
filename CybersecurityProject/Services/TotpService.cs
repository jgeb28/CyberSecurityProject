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
        var password =_httpContextAccessor.HttpContext?.Session.GetString("HashKey");
        if (password == null)
        {
            throw new InvalidOperationException("HashKey not found in session.");
        }
        
        var secretBytes = KeyGeneration.GenerateRandomKey(16);
        
        string encryptedSecret = Base32Encoding.ToString(_aesEncryptionService.EncryptKey(secretBytes, password));
        return encryptedSecret;
    }
    
    public string RegenerateTotpSecret(string secret)
    {
        var password =_httpContextAccessor.HttpContext?.Session.GetString("HashKey");
        if (password == null)
        {
            throw new InvalidOperationException("HashKey not found in session.");
        }
        
        byte[] secretBytes = Base32Encoding.ToBytes(secret);
        string encryptedSecret = Base32Encoding.ToString(_aesEncryptionService.EncryptKey(secretBytes, password));
        return encryptedSecret;
    }

    public async Task<bool> ValidateTotp(User user, UserManager<User> manager, string token)
    {
        var encryptedSecret = await manager.GetAuthenticatorKeyAsync(user);
        var secret = await GetDecryptedAuthenticatorKeyAsync(user, encryptedSecret);
        var secretBytes = Base32Encoding.ToBytes(secret);
        var totp = new Totp(secretBytes);
        
        return totp.VerifyTotp(token, out long timeStepMatched);
    }
    
    public Task<string> GetDecryptedAuthenticatorKeyAsync(User user, string encryptedSecret)
    {
        if (string.IsNullOrEmpty(encryptedSecret))
        {
            throw new InvalidOperationException("Authenticator key not found.");
        }

        var password = _httpContextAccessor.HttpContext?.Session.GetString("HashKey");
        if (string.IsNullOrEmpty(password))
        {
            throw new InvalidOperationException("HashKey not found in session.");
        }

        var encryptedSecretBytes = Base32Encoding.ToBytes(encryptedSecret);
        var secretBytes = _aesEncryptionService.DecryptKey(encryptedSecretBytes, password);
        string secret = Base32Encoding.ToString(secretBytes);
        
        return Task.FromResult(secret);
    }
}