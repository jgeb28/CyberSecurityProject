using CybersecurityProject.Models;
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
            User user = new User
            {
                UserName = viewModel.Username,
                Email = viewModel.Email,
            };
            
            var result = await _userManager.CreateAsync(user, viewModel.Password);

            if (result.Succeeded)
            {
                return RedirectToAction("Enable2FA", new { userId = user.Id });
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
    
    [HttpGet] [Route("/Account/Enable2FA/{userId}")]
    public async Task<IActionResult> Enable2FA(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }
        if (user.TwoFactorEnabled)
        {
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

            var model = new Enable2FAViewModel { Key = key, UserId = userId };
            return View(model);
        }
    }
    [HttpPost]
    public async Task<IActionResult> Confirm2FASetup(string code, string userId)
    {
        var user = await _userManager.FindByIdAsync(userId); 
        if (user == null)
        {
            return NotFound();
        }
        
        var isTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code);

        if (!isTokenValid)
        {
            ModelState.AddModelError("Code", "Verification code is invalid.");
            return View("Enable2FA"); 
        }
        
        await _userManager.SetTwoFactorEnabledAsync(user, true);
        
        await _signInManager.RefreshSignInAsync(user);

        return RedirectToAction("Index", "Home"); 
    }

    [HttpGet]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }

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
                await _signInManager.SignOutAsync();
                if (!user.TwoFactorEnabled)
                {
                    return RedirectToAction("Enable2FA", new { userId = user.Id } );
                }
                else
                {
                    return RedirectToAction("Error", "Home");
                }
                
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction("Login2FA");
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
    public IActionResult Login2FA()
    {
        return View();
    }
    [HttpPost]
    public async Task<IActionResult> Login2FA(Login2FAViewModel viewModel)
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


}

// TO DO: Pomyśleć czy nie przerzucić 2FA po loginie i nie dawać dostępu innym kontom.