using CybersecurityProject.Models;
using Microsoft.AspNetCore.Identity;

namespace CybersecurityProject.Services;

public class MyTotpTokenProvider : IUserTwoFactorTokenProvider<User>
{
    private TotpService _totpService;

    public MyTotpTokenProvider(TotpService totpService)
    {
        _totpService = totpService;
    }

    public Task<string> GenerateAsync(string purpose, UserManager<User> manager, User user)
    {
        return Task.FromResult(_totpService.GenerateTotpSecret());

    }

    public Task<bool> ValidateAsync(string purpose, string token, UserManager<User> manager, User user)
    {
        return _totpService.ValidateTotp(user, manager, token);
    }

    public async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<User> manager, User user)
    {
        var isTotpEnabled = await manager.GetTwoFactorEnabledAsync(user);
        
        return isTotpEnabled;
    }
}