using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using TokenAuthentication.API.Entities;
using TokenAuthentication.API.Models;

namespace TokenAuthentication.API.Repositories
{
    public class AuthRepository : IDisposable
    {
        /// <summary>
        /// Authentication DBContext
        /// </summary>
        private AuthContext _ctx;

        /// <summary>
        /// UserManager to handle users CRUD operations
        /// </summary>
        private UserManager<IdentityUser> _userManager;

        public AuthRepository()
        {
            _ctx = new AuthContext();
            _userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(_ctx));
        }

        #region Public methods for authentication
        /// <summary>
        /// Register new user
        /// </summary>
        /// <param name="userModel"></param>
        /// <returns></returns>
        public async Task<IdentityResult> RegisterUser(UserModel userModel)
        {
            IdentityUser user = new IdentityUser()
            {
                UserName = userModel.UserName,
                Email = userModel.Email,
            };

            var result = await _userManager.CreateAsync(user, userModel.Password);

            return result;
        }

        /// <summary>
        /// Find user bu login and password
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public async Task<IdentityUser> FindUser(string userName, string password)
        {
            IdentityUser user = await _userManager.FindAsync(userName, password);
            return user;
        }

        #endregion
        #region Methods for handling Clients and refreshToken
        public Client FindClient(string clientId)
        {
            var client = _ctx.Clients.Find(clientId);

            return client;
        }

        public async Task<bool> AddRefreshToken(RefreshToken token)
        {

            var existingToken = _ctx.RefreshTokens.Where(r => r.Subject == token.Subject && r.ClientId == token.ClientId).SingleOrDefault();

            if (existingToken != null)
            {
                var result = await RemoveRefreshToken(existingToken);
            }

            _ctx.RefreshTokens.Add(token);

            return await _ctx.SaveChangesAsync() > 0;
        }

        public async Task<bool> RemoveRefreshToken(string refreshTokenId)
        {
            var refreshToken = await _ctx.RefreshTokens.FindAsync(refreshTokenId);

            if (refreshToken != null)
            {
                _ctx.RefreshTokens.Remove(refreshToken);
                return await _ctx.SaveChangesAsync() > 0;
            }

            return false;
        }

        public async Task<bool> RemoveRefreshToken(RefreshToken refreshToken)
        {
            _ctx.RefreshTokens.Remove(refreshToken);
            return await _ctx.SaveChangesAsync() > 0;
        }

        public async Task<RefreshToken> FindRefreshToken(string refreshTokenId)
        {
            var refreshToken = await _ctx.RefreshTokens.FindAsync(refreshTokenId);

            return refreshToken;
        }

        public List<RefreshToken> GetAllRefreshTokens()
        {
            return _ctx.RefreshTokens.ToList();
        }
        #endregion

        #region Methods for handling external providers authentication
        public async Task<IdentityUser> FindAsync(UserLoginInfo loginInfo)
        {
            IdentityUser user = await _userManager.FindAsync(loginInfo);

            return user;
        }

        public async Task<IdentityResult> CreateAsync(IdentityUser user)
        {
            var result = await _userManager.CreateAsync(user);

            return result;
        }

        public async Task<IdentityResult> AddLoginAsync(string userId, UserLoginInfo login)
        {
            var result = await _userManager.AddLoginAsync(userId, login);

            return result;
        }
        #endregion
        /// <summary>
        /// Disposing
        /// </summary>
        public void Dispose()
        {
            _ctx.Dispose();
            _userManager.Dispose();
        }
    }
}