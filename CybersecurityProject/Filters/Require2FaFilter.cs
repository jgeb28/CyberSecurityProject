using CybersecurityProject.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace CybersecurityProject.Filters;

public class Require2FaFilter : Attribute, IAsyncActionFilter
{
    private readonly UserManager<User> _userManager;

    public Require2FaFilter(UserManager<User> userManager)
    {
        _userManager = userManager;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var user = context.HttpContext.User;

        if (user.Identity.IsAuthenticated)
        {
            var applicationUser = await _userManager.GetUserAsync(user);

            if (applicationUser == null)
            {
                context.Result = new RedirectToActionResult("Error", "Home", null);
                return;
            }
            if (!applicationUser.TwoFactorEnabled)
            {
                context.Result = new RedirectToActionResult("Enable2Fa", "Account", null);
                return;
            }
        }

        await next();
    }
}