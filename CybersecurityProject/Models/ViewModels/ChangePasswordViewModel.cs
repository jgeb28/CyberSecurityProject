using System.ComponentModel.DataAnnotations;

namespace CybersecurityProject.Models.ViewModels;

public class ChangePasswordViewModel
{
    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    [RegularExpression(@"^[a-zA-Z0-9@._-]+$", ErrorMessage = "Invalid characters in field.")]
    public string OldPassword { get; set; }
    [Required(ErrorMessage = "New Password is required")]
    [DataType(DataType.Password)]
    [RegularExpression(@"^[a-zA-Z0-9@._-]+$", ErrorMessage = "Invalid characters in field.")]
    [Compare("ConfirmPassword", ErrorMessage = "Passwords do not match")]
    public string NewPassword { get; set; }
    [Required(ErrorMessage = "Confirm Password is required")]
    [RegularExpression(@"^[a-zA-Z0-9@._-]+$", ErrorMessage = "Invalid characters in field.")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; }
    [Required]
    [RegularExpression(@"^[0-9]+$", ErrorMessage = "Invalid characters in field.")]
    public string Code { get; set; }
}