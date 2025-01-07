namespace CybersecurityProject.Models.ViewModels;

public class UserPostsViewModel
{
    public required string Username { get; set; }
    public required string PublicRsaKey { get; set; }
    public List<Post> Posts { get; set; } = new List<Post>();
}