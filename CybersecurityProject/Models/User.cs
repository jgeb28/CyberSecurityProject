using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace CybersecurityProject.Models;

public class User : IdentityUser
{
    [Required] [StringLength(5000)]
    public required string RsaPublicKey { get; set; }
    [Required] [StringLength(5000)]
    public required string RsaPrivateKeyEncrypted { get; set; }
    
    public List<Post> Posts { get; set; } = new List<Post>();
}