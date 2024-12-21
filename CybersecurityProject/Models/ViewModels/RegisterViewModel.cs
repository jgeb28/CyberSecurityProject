using System.ComponentModel.DataAnnotations;

namespace CybersecurityProject.Models.ViewModels;

public class RegisterViewModel
{
    [Required(ErrorMessage = "Username is required")]
    public string Username { get; set; }
    
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress]
    public string Email { get; set; }
    
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    [Compare("ConfirmPassword", ErrorMessage = "Passwords do not match")]
    public string Password { get; set; }
    
    [Required(ErrorMessage = "Confirm Password is required")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; }
}