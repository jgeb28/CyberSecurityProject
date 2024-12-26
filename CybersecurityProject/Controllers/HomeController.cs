using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using CybersecurityProject.Models;
using Microsoft.AspNetCore.Authorization;

namespace CybersecurityProject.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    public IActionResult Index()
    {
        return View();
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