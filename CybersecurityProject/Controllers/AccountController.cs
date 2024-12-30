using System.Security.Cryptography;
using Ganss.Xss;
using CybersecurityProject.Models;
using CybersecurityProject.Models.ViewModels;
using CybersecurityProject.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CybersecurityProject.Controllers;

public class AccountController : Controller
{
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;
    private readonly TotpService _totpService;
    private readonly AesEncryptionService _aesEncryptionService;

    public AccountController(
        SignInManager<User> signInManager,
        UserManager<User> userManager, 
        TotpService totpService,
        AesEncryptionService aesEncryptionService)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _totpService = totpService;
        _aesEncryptionService = aesEncryptionService;
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
    public async Task<IActionResult> Register(RegisterViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            var sanitizer = new HtmlSanitizer();
            string sanitizedUsername = sanitizer.Sanitize(viewModel.Username);
            string sanitizedEmail = sanitizer.Sanitize(viewModel.Email);

            RSA rsa = RSA.Create(2048);
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            string publicKeyString = Convert.ToBase64String(publicKey, Base64FormattingOptions.InsertLineBreaks);
            var privateKey = rsa.ExportPkcs8PrivateKey();
            string privateKeyString = Convert.ToBase64String(_aesEncryptionService.EncryptKey(privateKey, viewModel.Password), Base64FormattingOptions.InsertLineBreaks);
            
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
            return BadRequest();
        }
        if (user.TwoFactorEnabled)
        {
            TempData["Error"] = "Two-factor authentication already is enabled on this Account.";
            return RedirectToAction("Index", "Home");
        }
        else
        {
            var encryptedSecret = await _userManager.GetAuthenticatorKeyAsync(user);
            //if (encryptedSecret == null)
            //{
                var totpKey = await _userManager.GenerateTwoFactorTokenAsync(user, "MyTotpTokenProvider");
                await _userManager.SetAuthenticationTokenAsync(user, "[AspNetUserStore]", "AuthenticatorKey", totpKey);
                encryptedSecret = await _userManager.GetAuthenticatorKeyAsync(user);
            //}
            var key = await _totpService.GetDecryptedAuthenticatorKeyAsync(user, encryptedSecret);


            var model = new Enable2FaViewModel { Key = key, UserId = user.Id };
            return View(model);
        }
    }
    [Authorize]
    [HttpPost]
    public async Task<IActionResult> Confirm2FaSetup(string code)
    {
        var user = await _userManager.GetUserAsync(User); 
        if (user == null)
        {
            return BadRequest();
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
        
        await _userManager.SetTwoFactorEnabledAsync(user, true);
        
        return RedirectToAction("Index", "Home"); 
    }

    [HttpGet]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }
    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel viewModel)
    {
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
                return RedirectToAction("Login2Fa");
            }
            if (result.IsLockedOut)
            {
                return RedirectToPage("./Lockout");
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
    public async Task<IActionResult> Login2Fa(Login2FaViewModel viewModel)
    {
        if (Request.Cookies["Identity.TwoFactorUserId"] == null)
        {
            return RedirectToAction("Login");
        }
        var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
            viewModel.Code, 
            false, 
            false);

        if (result.Succeeded)
        {
            return RedirectToAction("Index", "Home");
        }
        else if (result.IsLockedOut)
        {
            return RedirectToPage("./Lockout");
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
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel viewModel)
    {
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
        
        var result = await _userManager.ChangePasswordAsync(user,viewModel.OldPassword,viewModel.NewPassword);
        
        if (result.Succeeded)
        {
            var rsaEncrypted = Convert.FromBase64String(user.RsaPrivateKeyEncrypted);
            var rsaDecrypted = _aesEncryptionService.DecryptKey(rsaEncrypted, viewModel.OldPassword);
            var refreshedRsaEncrypted = _aesEncryptionService.EncryptKey(rsaDecrypted, viewModel.NewPassword);
            user.RsaPrivateKeyEncrypted = Convert.ToBase64String(refreshedRsaEncrypted);
            await _userManager.UpdateAsync(user);
            GenerateSessionHashKey(viewModel.OldPassword);
            var encryptedSecret = await _userManager.GetAuthenticatorKeyAsync(user);
            var secret = await _totpService.GetDecryptedAuthenticatorKeyAsync(user, encryptedSecret);
            var totpKey = _totpService.RegenerateTotpSecret(secret);
            await _userManager.SetAuthenticationTokenAsync(user, "[AspNetUserStore]", "AuthenticatorKey", totpKey);
            
            await _signInManager.RefreshSignInAsync(user); 
            TempData["PasswordChangeSuccess"] = "Your password was changed successfully!";
            return RedirectToAction("Profile", "Home");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        return View(viewModel);
    }

    public void GenerateSessionHashKey(string password)
    {
        string saltString = "4pGAhQnhuanN1wMw4W35QA==\n";
        byte[] salt = Convert.FromBase64String(saltString);
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100, HashAlgorithmName.SHA256);
        string hashPassword = Convert.ToBase64String(pbkdf2.GetBytes(32));
        HttpContext.Session.SetString("HashKey", hashPassword);
    }

}

// TO DO: Przemyśleć czy i jak zaszyfrować sekret do 2FA