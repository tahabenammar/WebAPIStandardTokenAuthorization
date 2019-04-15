using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using TokenAuthentication.API.Models;

namespace TokenAuthentication.API.Infrastructure
{
    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        public ApplicationUserManager(IUserStore<ApplicationUser> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context)
        {
            var appDbContext = context.Get<AuthContext>();
            var appUserManager = new ApplicationUserManager(new UserStore<ApplicationUser>(appDbContext));

            #region Configure validation logic for usernames && passwords && custom validation
            //custom username validation
            /*appUserManager.UserValidator = new Validators.CustomUserValidator(appUserManager)
            {
                AllowOnlyAlphanumericUserNames = true,
                RequireUniqueEmail = true
            };*/
            //custom passwordvalidation
            /*appUserManager.PasswordValidator = new Validators.CustomPasswordValidator {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = false,
                RequireLowercase = true,
                RequireUppercase = true,
            };*/

            //standard username validator
            appUserManager.UserValidator = new UserValidator<ApplicationUser>(appUserManager)
            {
                AllowOnlyAlphanumericUserNames = true,
                RequireUniqueEmail = true
            };

            //standard password validator
            appUserManager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = false,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            #endregion

            #region configure email service for identity system
            appUserManager.EmailService = new Services.IdentityEmailService();

            //for sms service : appUserManager.SmsService=

            //Setting the expiration time for the code (token) send by the email to 6 hours, so if the user tried to open the confirmation email after 6 hours from receiving it, the code will be invalid.
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                appUserManager.UserTokenProvider = new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"))
                {
                    //Code for email confirmation and reset password life time
                    TokenLifespan = TimeSpan.FromHours(6)
                };
            }
            #endregion

            return appUserManager;
        }
    }
}