using CybersecurityProject.Data;
using CybersecurityProject.Models;
using CybersecurityProject.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Ganss.Xss;
using Microsoft.AspNetCore.Identity;

namespace CybersecurityProject.Controllers;

public class PostController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<User> _userManager;

    public PostController(ApplicationDbContext context, UserManager<User> userManager)
    {
        _context = context;
        _userManager = userManager;
    }
    
    [Authorize]
    [HttpGet]
    public IActionResult AddPost()
    {
        return View();
    }

    [Authorize]
    [HttpPost]
public async Task<IActionResult> AddPost(PostViewModel viewModel)
    {
        if (!ModelState.IsValid)
        {
            return View(viewModel);
        }
        
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return BadRequest();
        }
        var sanitizer = new HtmlSanitizer();
        sanitizer.AllowedSchemes.Add("data");
        sanitizer.AllowedAttributes.Add("style");
        sanitizer.AllowedCssProperties.Add("width");
        sanitizer.AllowedCssProperties.Add("height");
        var sanitized = sanitizer.Sanitize(viewModel.Content);

        Post post = new Post
        {
            Title = viewModel.Title,
            Content = sanitized,
            Author = user 
        };
        
        _context.Posts.Add(post);
        await _context.SaveChangesAsync();
        
        return RedirectToAction("Index", "Home");
    }
}