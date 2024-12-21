using CybersecurityProject.Models;
using CybersecurityProject.Models.dto;
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
}

// TO DO: Pomyśleć czy nie przerzucić 2FA po loginie i nie dawać dostępu innym kontom.