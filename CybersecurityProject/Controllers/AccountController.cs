using System.Security.Cryptography;
using Ganss.Xss;
using CybersecurityProject.Models;
using CybersecurityProject.Filters;
using CybersecurityProject.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CybersecurityProject.Controllers;

public class AccountController : Controller
{
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;

    public AccountController(SignInManager<User> signInManager, UserManager<User> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
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
            string privateKeyString = Convert.ToBase64String(EncryptRsaKey(privateKey, viewModel.Password), Base64FormattingOptions.InsertLineBreaks);
            
            User user = new User
            {
                UserName = sanitizedUsername,
                Email = sanitizedEmail,
                RsaPublicKey = publicKeyString,
                RsaPrivateKeyEncrypted = privateKeyString
            };
            
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
            var key = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
            }

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
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code);

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

    public byte[] EncryptRsaKey(byte[] rsaKey, string password)
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
        cryptStream.Write(rsaKey, 0, rsaKey.Length); 
        cryptStream.FlushFinalBlock();
        
        byte[] ciphertext = fileStream.ToArray();
        byte[] encryptedData = new byte[salt.Length + iv.Length + ciphertext.Length];
        Buffer.BlockCopy(salt, 0, encryptedData, 0, salt.Length);
        Buffer.BlockCopy(iv, 0, encryptedData, salt.Length, iv.Length);
        Buffer.BlockCopy(ciphertext, 0, encryptedData, salt.Length + iv.Length, ciphertext.Length);

        return encryptedData;
    }
    
    public byte[] DecryptRsaKey(byte[] rsaCipher, string password)
    {
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[rsaCipher.Length - salt.Length - iv.Length];
       
        Buffer.BlockCopy(rsaCipher, 0, salt, 0, salt.Length);
        Buffer.BlockCopy(rsaCipher, salt.Length, iv, 0, iv.Length);
        Buffer.BlockCopy(rsaCipher, salt.Length + iv.Length, ciphertext, 0, ciphertext.Length);
        
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
        
        var is2FaValid = await _userManager.VerifyTwoFactorTokenAsync(user, "Authenticator", viewModel.Code);
        if (!is2FaValid)
        {
            ModelState.AddModelError("Code", "Invalid code.");
            return View(viewModel);
        }
        
        var result = await _userManager.ChangePasswordAsync(user,viewModel.OldPassword,viewModel.NewPassword);
        if (result.Succeeded)
        {
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


}

// TO DO: Przemyśleć czy i jak zaszyfrować sekret do 2FA