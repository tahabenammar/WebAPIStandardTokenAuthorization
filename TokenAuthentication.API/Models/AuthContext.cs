using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;
using TokenAuthentication.API.Entities;

namespace TokenAuthentication.API.Models
{
    public class AuthContext : IdentityDbContext<IdentityUser>
    {
        public DbSet<Client> Clients { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        
        public AuthContext() : base("AuthContext")
        {
            Configuration.ProxyCreationEnabled = false;
            Configuration.LazyLoadingEnabled = false;
        }

        public static AuthContext Create()
        {
            return new AuthContext();
        }
        
    }
}