using System.ComponentModel.DataAnnotations;

namespace CybersecurityProject.Models;

public class Post
{
    [Key]
    public int Id { get; set; }
    
    [Required][StringLength(200)]
    public required string Title { get; set; }
    
    [Required] [StringLength(10000)]
    public required string Content { get; set; }
    
    [StringLength(1000)]
    public string? Image { get; set; }
}