using System.Diagnostics;
using CybersecurityProject.Data;
using Microsoft.AspNetCore.Mvc;
using CybersecurityProject.Models;
using CybersecurityProject.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace CybersecurityProject.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly ApplicationDbContext _context;

    public HomeController(ILogger<HomeController> logger, ApplicationDbContext context)
    {
        _logger = logger;
        _context = context;
    }

    public async Task<IActionResult> Index()
    {
        var posts = await _context.Posts
            .Select(p => new PostDisplayViewModel
            {
                Post = p,
                AuthorName = p.Author.UserName 
            })
            .ToListAsync();

        return View(posts);
    }
    [HttpGet("/Lockout")]
    public IActionResult Lockout()
    {
        return View();
    }
    
    [Authorize]
    [HttpGet("/Profile")]
    public IActionResult Profile()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}