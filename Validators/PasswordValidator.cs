using System.Text.RegularExpressions;

namespace DyanamicsAPI.Validators
{
    public static class PasswordValidator
    {
        public static (bool IsValid, string Message) Validate(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return (false, "Password cannot be empty");

            if (password.Length < 8)
                return (false, "Password must be at least 8 characters");

            if (!Regex.IsMatch(password, @"[A-Z]"))
                return (false, "Password must contain at least one uppercase letter");

            if (!Regex.IsMatch(password, @"[a-z]"))
                return (false, "Password must contain at least one lowercase letter");

            if (!Regex.IsMatch(password, @"[0-9]"))
                return (false, "Password must contain at least one number");

            if (!Regex.IsMatch(password, @"[^a-zA-Z0-9]"))
                return (false, "Password must contain at least one special character");

            if (password.Contains(" "))
                return (false, "Password cannot contain spaces");

            return (true, "Password is valid");
        }
    }
}