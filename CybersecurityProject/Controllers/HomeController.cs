using System.Diagnostics;
using CybersecurityProject.Data;
using Microsoft.AspNetCore.Mvc;
using CybersecurityProject.Models;
using CybersecurityProject.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using CybersecurityProject.Filters;


namespace CybersecurityProject.Controllers;

public class HomeController : Controller
{
    private readonly ApplicationDbContext _context;

    public HomeController(ApplicationDbContext context)
    {
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
            .OrderByDescending(e => e.Post.Id)
            .Take(5)
            .ToListAsync();

        return View(posts);
    }
    [HttpGet("/Lockout")]
    public IActionResult Lockout()
    {
        return View();
    }
    
    [Authorize]
    [ServiceFilter(typeof(Require2FaFilter))]
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