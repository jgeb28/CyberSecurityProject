using System.ComponentModel.DataAnnotations;
using System.Net.Mime;

namespace CybersecurityProject.Models.ViewModels;

public class PostViewModel
{
    [Required][StringLength(200)]
    public required string Title { get; init; }
    
    [Required(ErrorMessage = "Content is required.")][StringLength(3000, ErrorMessage = "Your content is to big, consider adding smaller file or less text.")]
    public required string Content { get; init; }
    
}