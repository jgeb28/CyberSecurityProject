using CybersecurityProject.Data;
using CybersecurityProject.Models;
using CybersecurityProject.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Ganss.Xss;
using Microsoft.AspNetCore.Identity;
using CybersecurityProject.Services;
using Microsoft.EntityFrameworkCore;


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
    [ServiceFilter(typeof(Require2FaFilter))]
    [HttpGet]
    public IActionResult AddPost()
    {
        return View();
    }

    [Authorize]
    [ServiceFilter(typeof(Require2FaFilter))]
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

    [HttpGet("/{username}")]
    public async Task<IActionResult> UserPosts(string username)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user == null)
        {
            return NotFound();
        }
        
        var posts = _context.Posts.Select(post => post)
            .Where(post => post.Author == user)
            .ToList();
        UserPostsViewModel viewModel = new UserPostsViewModel
        {
           Posts = posts,
           Username = user.UserName,
           PublicRsaKey = user.RsaPublicKey
        };

        return View(viewModel);
    }

    [HttpPost]
    public async Task<IActionResult> DeletePost(string postId)
    {
        var post = await _context.Posts
            .Include(p => p.Author) 
            .FirstOrDefaultAsync(p => p.Id == int.Parse(postId)); 
        if (post == null)
        {
            return NotFound();
        }
        var user = await _userManager.GetUserAsync(User);
        if (user != post.Author)
        {
            return Forbid();
        }
        _context.Posts.Remove(post);
        await _context.SaveChangesAsync();
        TempData["Success"] = "Post deleted successfully.";
        
        return RedirectToAction("UserPosts", new { username = user.UserName });
    }
    
}