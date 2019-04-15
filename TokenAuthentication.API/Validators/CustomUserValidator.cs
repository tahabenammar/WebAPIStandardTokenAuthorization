using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using TokenAuthentication.API.Infrastructure;

namespace TokenAuthentication.API.Validators
{
    public class CustomUserValidator : UserValidator<ApplicationUser>
    {

        List<string> _allowedEmailDomains = new List<string> { "outlook.com", "hotmail.com", "gmail.com", "yahoo.com" };

        public CustomUserValidator(ApplicationUserManager appUserManager)
            : base(appUserManager)
        {
        }

        public override async Task<IdentityResult> ValidateAsync(ApplicationUser user)
        {
            //Appliquer la validation de base from ApplicationUserManager
            IdentityResult result = await base.ValidateAsync(user);

            var emailDomain = user.Email.Split('@')[1];

            if (!_allowedEmailDomains.Contains(emailDomain.ToLower()))
            {
                var errors = result.Errors.ToList();

                errors.Add(String.Format("Email domain '{0}' is not allowed", emailDomain));

                result = new IdentityResult(errors);
            }

            return result;
        }
    }
}