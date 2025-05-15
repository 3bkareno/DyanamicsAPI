// ChangePasswordDto.cs
using DyanamicsAPI.Validators;
using FluentValidation;

namespace DyanamicsAPI.DTOs
{
    public class ChangePasswordDto
    {
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class ChangePasswordValidator : AbstractValidator<ChangePasswordDto>
    {
        public ChangePasswordValidator()
        {
            RuleFor(x => x.CurrentPassword).NotEmpty();
            RuleFor(x => x.NewPassword).NotEmpty()
                .Must(p => PasswordValidator.Validate(p).IsValid)
                .WithMessage(p => PasswordValidator.Validate(p.NewPassword).Message)
                .NotEqual(x => x.CurrentPassword)
                .WithMessage("يجب أن تكون كلمة المرور الجديدة مختلفة عن كلمة المرور الحالية");
        }
    }
}