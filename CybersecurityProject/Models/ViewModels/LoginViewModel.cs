using System.ComponentModel.DataAnnotations;

namespace CybersecurityProject.Models.ViewModels;

public class LoginViewModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress]
    public required string Email { get; init; }
    
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    public required string Password { get; init; }
    
}