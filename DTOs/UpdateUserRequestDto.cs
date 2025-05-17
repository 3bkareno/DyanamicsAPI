using DyanamicsAPI.Models;
using DyanamicsAPI.Validators;
using FluentValidation;

namespace DyanamicsAPI.DTOs
{
    public class UpdateUserRequestDto
    {
        public string? Username { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
        public UserRole? Role { get; set; }
    }

    public class UpdateUserRequestValidator : AbstractValidator<UpdateUserRequestDto>
    {
        public UpdateUserRequestValidator()
        {
            RuleFor(x => x.Username).MinimumLength(2).When(x => x.Username != null);
            RuleFor(x => x.Email).EmailAddress().When(x => x.Email != null);
            RuleFor(x => x.Password)
                .Must(p => PasswordValidator.Validate(p).IsValid)
                .When(x => !string.IsNullOrEmpty(x.Password))
                .WithMessage(p => PasswordValidator.Validate(p.Password).Message);
            RuleFor(x => x.Role).IsInEnum().When(x => x.Role != null);
        }
    }
}