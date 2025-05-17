using DyanamicsAPI.DTOs;
using FluentValidation;

namespace DyanamicsAPI.Validators
{
    public class AddUserRequestDtoValidator : AbstractValidator<AddUserRequestDto>
    {
        public AddUserRequestDtoValidator()
        {
            RuleFor(x => x.Username)
                .NotEmpty()
                .MinimumLength(2);

            RuleFor(x => x.Password)
                .NotEmpty()
                .MinimumLength(6);

            RuleFor(x => x.Email)
                .NotEmpty()
                .EmailAddress();

            RuleFor(x => x.Role)
                .IsInEnum();
        }
    }
}
