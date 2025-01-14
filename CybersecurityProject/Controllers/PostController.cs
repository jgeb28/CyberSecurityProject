using System.Security.Cryptography;
using System.Text;
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
    private readonly AesEncryptionService _encryptionService;

    public PostController(ApplicationDbContext context, UserManager<User> userManager, AesEncryptionService encryptionService)
    {
        _context = context;
        _userManager = userManager;
        _encryptionService = encryptionService;
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
    [ValidateAntiForgeryToken]
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

        if (viewModel.IsVerified == true)
        {
            if (!await _userManager.CheckPasswordAsync(user, viewModel.Password))
            {
                ModelState.AddModelError("Password", "Incorrect password.");
                return View(viewModel);
            }
        }

        string signature = "";
        bool verified = false;
        var sanitizer = new HtmlSanitizer();
        var sanitized = sanitizer.Sanitize(viewModel.Content);

        if (viewModel.IsVerified == true)
        {
            var rsaEncrypted = user.RsaPrivateKeyEncrypted;
            var rsaDecrypted =
                _encryptionService.DecryptKey(Convert.FromBase64String(rsaEncrypted), viewModel.Password);
            using var rsa = RSA.Create();

            rsa.ImportPkcs8PrivateKey(rsaDecrypted, out _);
            byte[] data = Encoding.UTF8.GetBytes(sanitized);

            byte[] signatureBytes = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(user.RsaPublicKey), out _);
            bool isVerified = rsa.VerifyData(data, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (!isVerified)
            {
                ModelState.AddModelError(string.Empty, "Something went wrong.");
                return View(viewModel);
            }

            signature = Convert.ToBase64String(signatureBytes, Base64FormattingOptions.InsertLineBreaks);
            verified = true;
            Console.WriteLine("RSA");
            Console.WriteLine(signature);
            Console.WriteLine("");
            Console.WriteLine(user.RsaPublicKey);
            Console.WriteLine("");
            Console.WriteLine(sanitized);

        }

        Post post = new Post
        {
            Title = viewModel.Title,
            Content = sanitized,
            Author = user,
            IsVerified = verified,
            RsaSignature = signature
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
            .Where(post => post.Author == user).OrderByDescending(post => post.Id)
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
    [ValidateAntiForgeryToken]
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