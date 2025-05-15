using System.Text.RegularExpressions;

namespace DyanamicsAPI.Validators
{
    public static class PasswordValidator
    {
        public static (bool IsValid, string Message) Validate(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return (false, "لا يمكن أن تكون كلمة المرور فارغة");

            if (password.Length < 8)
                return (false, "يجب أن تتكون كلمة المرور من 8 أحرف على الأقل");

            if (!Regex.IsMatch(password, @"[A-Z]"))
                return (false, "يجب أن تحتوي كلمة المرور على حرف كبير واحد على الأقل");

            if (!Regex.IsMatch(password, @"[a-z]"))
                return (false, "يجب أن تحتوي كلمة المرور على حرف صغير واحد على الأقل");

            if (!Regex.IsMatch(password, @"[0-9]"))
                return (false, "يجب أن تحتوي كلمة المرور على رقم واحد على الأقل");

            if (!Regex.IsMatch(password, @"[^a-zA-Z0-9]"))
                return (false, "يجب أن تحتوي كلمة المرور على حرف خاص واحد على الأقل");

            if (password.Contains(" "))
                return (false, "لا يمكن أن تحتوي كلمة المرور على مسافات");

            return (true, "كلمة المرور صالحة");
        }
    }
}