using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using TokenAuthentication.API.Entities;
using TokenAuthentication.API.Infrastructure;
using TokenAuthentication.API.Repositories;
using TokenAuthentication.API.Tools;

namespace TokenAuthentication.API.Providers
{
    public class CustomAuthorisationServerProvider : OAuthAuthorizationServerProvider
    {
        /// <summary>
        /// Responsible for validating the “Client” subscribed to the API, 
        /// in our case we have only one client so we’ll always return that its validated successfully
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId = string.Empty;
            string clientSecret = string.Empty;
            Client client = null;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (context.ClientId == null)
            {
                //Remove the comments from the below line context.SetError, and invalidate context 
                //if you want to force sending clientId/secrects once obtain access tokens. 
                context.Validated();
                //context.SetError("invalid_clientId", "ClientId should be sent.");
                return Task.FromResult<object>(null);
            }

            using (AuthRepository _repo = new AuthRepository())
            {
                client = _repo.FindClient(context.ClientId);
            }

            if (client == null)
            {
                context.SetError("invalid_clientId", string.Format("Client '{0}' is not registered in the system.", context.ClientId));
                return Task.FromResult<object>(null);
            }

            if (client.ApplicationType == Models.ApplicationTypes.NativeConfidential)
            {
                if (string.IsNullOrWhiteSpace(clientSecret))
                {
                    context.SetError("invalid_clientId", "Client secret should be sent.");
                    return Task.FromResult<object>(null);
                }
                else
                {
                    if (client.Secret != Helper.GetHash(clientSecret))
                    {
                        context.SetError("invalid_clientId", "Client secret is invalid.");
                        return Task.FromResult<object>(null);
                    }
                }
            }

            if (!client.Active)
            {
                context.SetError("invalid_clientId", "Client is inactive.");
                return Task.FromResult<object>(null);
            }

            context.OwinContext.Set<string>("as:clientAllowedOrigin", client.AllowedOrigin);
            context.OwinContext.Set<string>("as:clientRefreshTokenLifeTime", client.RefreshTokenLifeTime.ToString());

            context.Validated();
            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// Responsible to validate the username and password sent to the authorization server’s token endpoint
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");

            if (allowedOrigin == null) allowedOrigin = "*";

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            //using (AuthRepository _repo = new AuthRepository())
            //{
            //    IdentityUser user = await _repo.FindUser(context.UserName, context.Password);

            //    if (user == null)
            //    {
            //        context.SetError("invalid_grant", "The user name or password is incorrect.");
            //        return;
            //    }
            //}

            //var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            //identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            //identity.AddClaim(new Claim("sub", context.UserName));
            //identity.AddClaim(new Claim(ClaimTypes.Role, "user"));
            var userManager = context.OwinContext.GetUserManager<ApplicationUserManager>();
            var roleManager = context.OwinContext.GetUserManager<ApplicationRoleManager>();
            ApplicationUser user = await userManager.FindAsync(context.UserName, context.Password);

            if (user == null)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return;
            }

            if (!user.EmailConfirmed)
            {
                context.SetError("invalid_grant", "User did not confirm email.");
                return;
            }
            //generate the identity to pass to the tikcet 
            ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(userManager, context.Options.AuthenticationType);
            oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            oAuthIdentity.AddClaim(new Claim("sub", context.UserName));
            //Add all roles of current user
            List<Claim> rolesClaims = new List<Claim>();
            foreach (var identityUserRole in user.Roles)
            {
                var identityRole = await roleManager.FindByIdAsync(identityUserRole.RoleId);
                rolesClaims.Add(new Claim(ClaimTypes.Role, identityRole.Name));
            }
            oAuthIdentity.AddClaims(rolesClaims);

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    {
                        "as:client_id", (context.ClientId == null) ? string.Empty : context.ClientId
                    },
                    {
                        "userName", context.UserName
                    }
                });

            var ticket = new AuthenticationTicket(oAuthIdentity, props);
            context.Validated(ticket);
            #region authentication token without reffresh toke
            //context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            //using (AuthRepository _repo = new AuthRepository())
            //{
            //    IdentityUser user = await _repo.FindUser(context.UserName, context.Password);

            //    if (user == null)
            //    {
            //        context.SetError("invalid_grant", "The user name or password is incorrect.");
            //        return;
            //    }
            //}

            //var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            ////sub is equivalent to nameidentifier
            //identity.AddClaim(new Claim("sub", context.UserName));
            //identity.AddClaim(new Claim(ClaimTypes.Role, "user"));

            //context.Validated(identity);
            #endregion

        }


        /// <summary>
        /// Called at the final stage of a successful Token endpoint request. An application
        ///     may implement this call in order to do any final modification of the claims being
        ///     used to issue access or refresh tokens. This call may also be used in order to
        ///     add additional response parameters to the Token endpoint's json response body.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// Called when a request to the Token endpoint arrives with a "grant_type" of "refresh_token".
        ///     This occurs if your application has issued a "refresh_token" along with the "access_token",
        ///     and the client is attempting to use the "refresh_token" to acquire a new "access_token",
        ///    and possibly a new "refresh_token". To issue a refresh token the an Options.RefreshTokenProvider
        ///     must be assigned to create the value which is returned. The claims and properties
        ///     associated with the refresh token are present in the context.Ticket. The application
        ///     must call context.Validated to instruct the Authorization Server middleware to
        ///     issue an access token based on those claims and properties. The call to context.Validated
        ///     may be given a different AuthenticationTicket or ClaimsIdentity in order to control
        ///     which information flows from the refresh token to the access token. The default
        ///     behavior when using the OAuthAuthorizationServerProvider is to flow information
        ///     from the refresh token to the access token unmodified. See also http://tools.ietf.org/html/rfc6749#section-6
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }

            // Change auth ticket for refresh token requests
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);
            newIdentity.AddClaim(new Claim("newClaim", "newValue"));

            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
        }
    }
}