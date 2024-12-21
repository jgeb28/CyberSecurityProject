using System.ComponentModel.DataAnnotations;

namespace CybersecurityProject.Models.ViewModels;

public class Login2FAViewModel
{
    [Required]
    public string Code { get; set; }
}