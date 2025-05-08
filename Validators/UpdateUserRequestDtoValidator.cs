using DyanamicsAPI.DTOs;
using FluentValidation;

namespace DyanamicsAPI.Validators
{
    public class UpdateUserRequestDtoValidator : AbstractValidator<UpdateUserRequestDto>
    {
        public UpdateUserRequestDtoValidator()
        {
            RuleFor(x => x.Email)
                .EmailAddress()
                .When(x => !string.IsNullOrEmpty(x.Email));

            RuleFor(x => x.Username)
                .MinimumLength(3)
                .When(x => !string.IsNullOrEmpty(x.Username));

            RuleFor(x => x.Password)
                .MinimumLength(6)
                .When(x => !string.IsNullOrEmpty(x.Password));

            RuleFor(x => x.Role)
                .IsInEnum()
                .When(x => x.Role != null);
        }
    }
}
