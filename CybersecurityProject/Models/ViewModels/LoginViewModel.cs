using System.ComponentModel.DataAnnotations;

namespace CybersecurityProject.Models.ViewModels;

public class LoginViewModel
{
    [Required(ErrorMessage = "Email is required")]
    [RegularExpression(@"^[a-zA-Z0-9@._-]+$", ErrorMessage = "Invalid characters in field.")]
    [EmailAddress]
    public required string Email { get; set; }
    
    [Required(ErrorMessage = "Password is required")]
    [RegularExpression(@"^[a-zA-Z0-9@#._-]+$", ErrorMessage = "Invalid characters in field.")]
    [DataType(DataType.Password)]
    public required string Password { get; set; }
    
}