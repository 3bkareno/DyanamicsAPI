using DyanamicsAPI.Models;
using DyanamicsAPI.Validators;
using FluentValidation;

namespace DyanamicsAPI.DTOs
{
    public class AddUserRequestDto
    {
       
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public UserRole Role { get; set; }
    }

    public class AddUserRequestValidator : AbstractValidator<AddUserRequestDto>
    {
        public AddUserRequestValidator()
        {
            
            RuleFor(x => x.Username).NotEmpty().MinimumLength(2);
            RuleFor(x => x.Email).NotEmpty().EmailAddress();
            RuleFor(x => x.Password).NotEmpty().Must(p => PasswordValidator.Validate(p).IsValid)
                .WithMessage(p => PasswordValidator.Validate(p.Password).Message);
            RuleFor(x => x.Role).IsInEnum();
        }
    }
}