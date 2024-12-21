using Microsoft.AspNetCore.Identity;

namespace CybersecurityProject.Models;

public class User : IdentityUser
{
    public List<Post> Posts { get; set; } = new List<Post>();
}