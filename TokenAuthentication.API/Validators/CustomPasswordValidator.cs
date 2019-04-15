using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace TokenAuthentication.API.Validators
{
    public class CustomPasswordValidator : PasswordValidator
    {
        private Regex regexItem = new Regex(@"[!@#$%^&*()_+=\[{\]};:<>|./?,-]", RegexOptions.Compiled);

        public override async Task<IdentityResult> ValidateAsync(string password)
        {
            IdentityResult result = await base.ValidateAsync(password);

            if (!regexItem.IsMatch(password))
            {
                var errors = result.Errors.ToList();
                errors.Add("Password should contain At least one special case characters");
                result = new IdentityResult(errors);
            }
            return result;
        }
    }
}