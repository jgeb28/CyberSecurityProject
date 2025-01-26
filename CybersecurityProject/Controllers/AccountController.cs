using System.Security.Cryptography;
using CybersecurityProject.Data;
using Ganss.Xss;
using CybersecurityProject.Models;
using CybersecurityProject.Models.ViewModels;
using CybersecurityProject.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OtpNet;

namespace CybersecurityProject.Controllers;

public class AccountController : Controller
{
    private readonly ApplicationDbContext _dbContext;
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;
    private readonly TotpService _totpService;
    private readonly AesEncryptionService _aesEncryptionService;

    public AccountController(
        SignInManager<User> signInManager,
        UserManager<User> userManager, 
        TotpService totpService,
        AesEncryptionService aesEncryptionService,
        ApplicationDbContext dbContext)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _totpService = totpService;
        _aesEncryptionService = aesEncryptionService;
        _dbContext = dbContext;
    }
    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }
    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }
    
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            var sanitizer = new HtmlSanitizer();
            string sanitizedUsername = sanitizer.Sanitize(viewModel.Username);
            string sanitizedEmail = sanitizer.Sanitize(viewModel.Email);

            using RSA rsa = RSA.Create(2048);
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            string publicKeyString = Convert.ToBase64String(publicKey, Base64FormattingOptions.InsertLineBreaks);
            var privateKey = rsa.ExportPkcs8PrivateKey();
            string privateKeyString = Convert.ToBase64String(_aesEncryptionService.EncryptKey(privateKey, viewModel.Password));
            User user = new User
            {
                UserName = sanitizedUsername,
                Email = sanitizedEmail,
                RsaPublicKey = publicKeyString,
                RsaPrivateKeyEncrypted = privateKeyString
            };
            GenerateSessionHashKey(viewModel.Password);
            
            var result = await _userManager.CreateAsync(user, viewModel.Password);

            if (result.Succeeded)
            {
                return RedirectToAction("Login");
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                
                return View(viewModel);
            }
            
        }
        return View(viewModel);
    }
    
    [Authorize]
    [HttpGet]
    public async Task<IActionResult> Enable2Fa()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return BadRequest("User not found");
        }
        if (user.TwoFactorEnabled)
        {
            TempData["Error"] = "Two-factor authentication already is enabled on this Account.";
            return RedirectToAction("Index", "Home");
        }
        else
        {
            var encryptedSecret = await _userManager.GetAuthenticatorKeyAsync(user);
            if (encryptedSecret == null)
            {
                var totpKey = await _userManager.GenerateTwoFactorTokenAsync(user, "MyTotpTokenProvider");
                await _userManager.SetAuthenticationTokenAsync(user, "[AspNetUserStore]", "AuthenticatorKey", totpKey);
                encryptedSecret = await _userManager.GetAuthenticatorKeyAsync(user);
            }
            var key = await _totpService.GetDecryptedAuthenticatorKeyAsync(user, encryptedSecret);


            var model = new Enable2FaViewModel { Key = key, UserId = user.Id };
            return View(model);
        }
    }
    [Authorize]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Confirm2FaSetup(string code)
    {
        var user = await _userManager.GetUserAsync(User); 
        if (user == null)
        {
            return BadRequest("User not found");
        }
        if (user.TwoFactorEnabled)
        {
            TempData["Error"] = "Two-factor authentication already is enabled on this Account.";
            return RedirectToAction("Index", "Home");
        }
        
        var isTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, "MyTotpTokenProvider", code);

        if (!isTokenValid)
        {
            TempData["Error2FA"] = "Invalid code";
            return RedirectToAction("Enable2Fa", new { user.Id }); 
        }
        
        HttpContext.Session.Remove("HashKey");
        await _userManager.SetTwoFactorEnabledAsync(user, true);
        
        return RedirectToAction("Index", "Home"); 
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }
    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel viewModel)
    {
        await Task.Delay(1000);
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByEmailAsync(viewModel.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(viewModel);
            }
            
            var result = await _signInManager.PasswordSignInAsync(user.UserName, viewModel.Password, false, true);

            if (result.Succeeded)
            {
                GenerateSessionHashKey(viewModel.Password);
                if (!user.TwoFactorEnabled)
                {
                    return RedirectToAction("Enable2Fa");
                }
                else
                {
                    return RedirectToAction("Error", "Home");
                }
                
            }
            if (result.RequiresTwoFactor)
            {
                GenerateSessionHashKey(viewModel.Password);
                return RedirectToAction("Login2Fa");
            }
            if (result.IsLockedOut)
            {
                return RedirectToAction("Lockout", "Home");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(viewModel);
            }
            
        }
        return View(viewModel);
    }

    [HttpGet]
    public IActionResult Login2Fa()
    {
        return View();
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login2Fa(Login2FaViewModel viewModel)
    {
        if (Request.Cookies["Identity.TwoFactorUserId"] == null || HttpContext.Session.GetString("HashKey") == null)
        {
            return RedirectToAction("Login");
        }
        await Task.Delay(1000);
        var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
            viewModel.Code, 
            false, 
            false);
        if (result.Succeeded)
        {
            HttpContext.Session.Remove("HashKey");
            return RedirectToAction("Index", "Home");
        }
        else if (result.IsLockedOut)
        {
            HttpContext.Session.Remove("HashKey");
            return RedirectToAction("Lockout" ,"Home");
        }
        else
        {
            ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
            return View(viewModel);
        }
    }
    
    [Authorize]
    [ServiceFilter(typeof(Require2FaFilter))]
    [HttpGet]
    public IActionResult ChangePassword()
    {
        return View();
    }

    [Authorize]
    [ServiceFilter(typeof(Require2FaFilter))]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel viewModel)
    {
        await Task.Delay(1000);
        if (!ModelState.IsValid)
        {
            return View(viewModel);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction("Login");
        }
        GenerateSessionHashKey(viewModel.OldPassword);
        var is2FaValid = await _userManager.VerifyTwoFactorTokenAsync(user, "MyTotpTokenProvider", viewModel.Code);
        if (!is2FaValid)
        {
            ModelState.AddModelError("Code", "Invalid code.");
            return View(viewModel);
        }
        
        await using (var transaction = await _dbContext.Database.BeginTransactionAsync())
        {
            try
            {
                var result = await _userManager.ChangePasswordAsync(user, viewModel.OldPassword, viewModel.NewPassword);
                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    return View(viewModel);
                }

                var rsaEncrypted = Convert.FromBase64String(user.RsaPrivateKeyEncrypted);
                var rsaDecrypted = _aesEncryptionService.DecryptKey(rsaEncrypted, viewModel.OldPassword);
                var refreshedRsaEncrypted = _aesEncryptionService.EncryptKey(rsaDecrypted, viewModel.NewPassword);
                user.RsaPrivateKeyEncrypted = Convert.ToBase64String(refreshedRsaEncrypted);

                await _userManager.UpdateAsync(user);

                var encryptedSecret = await _userManager.GetAuthenticatorKeyAsync(user);
                GenerateSessionHashKey(viewModel.OldPassword);
                var secret = await _totpService.GetDecryptedAuthenticatorKeyAsync(user, encryptedSecret);
                HttpContext.Session.Remove("HashKey");
                
                GenerateSessionHashKey(viewModel.NewPassword);
                var totpKey = _totpService.RegenerateTotpSecret(secret);
                await _userManager.SetAuthenticationTokenAsync(user, "[AspNetUserStore]", "AuthenticatorKey", totpKey);
                HttpContext.Session.Remove("HashKey");

                await transaction.CommitAsync();

                await _signInManager.RefreshSignInAsync(user);
                TempData["PasswordChangeSuccess"] = "Your password was changed successfully!";
                return RedirectToAction("Profile", "Home");
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                ModelState.AddModelError(string.Empty, "An error occurred while updating your credentials. Please try again.");
                return View(viewModel);
            }
        }
    }

    public void GenerateSessionHashKey(string password)
    {
        string saltString = "4pGAhQnhuanN1wMw4W35QA==\n";
        byte[] salt = Convert.FromBase64String(saltString);
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10_000, HashAlgorithmName.SHA256);
        string hashPassword = Convert.ToBase64String(pbkdf2.GetBytes(32));
        HttpContext.Session.SetString("HashKey", hashPassword);
    }

}

