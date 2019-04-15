namespace TokenAuthentication.API.Migrations
{
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.EntityFramework;
    using System;
    using System.Collections.Generic;
    using System.Data.Entity;
    using System.Data.Entity.Migrations;
    using System.Linq;
    using TokenAuthentication.API.Entities;
    using TokenAuthentication.API.Infrastructure;
    using TokenAuthentication.API.Models;
    using TokenAuthentication.API.Tools;

    internal sealed class Configuration : DbMigrationsConfiguration<TokenAuthentication.API.Models.AuthContext>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = false;
            ContextKey = "TokenAuthentication.API.Models.AuthContext";
        }

        protected override void Seed(TokenAuthentication.API.Models.AuthContext context)
        {
            //  This method will be called after migrating to the latest version.

            //  You can use the DbSet<T>.AddOrUpdate() helper extension method 
            //  to avoid creating duplicate seed data. E.g.
            //
            //    context.People.AddOrUpdate(
            //      p => p.FullName,
            //      new Person { FullName = "Andrew Peters" },
            //      new Person { FullName = "Brice Lambson" },
            //      new Person { FullName = "Rowan Miller" }
            //    );
            //
            var manager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new AuthContext()));
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(new AuthContext()));

            var user = new ApplicationUser()
            {
                UserName = "superAdmin",
                Email = "super-admin@domain.com",
                EmailConfirmed = true,
                FirstName = "Taha",
                LastName = "Ben Ammar",
                Level = 1,
                JoinDate = DateTime.Now.AddYears(-3),
                Birthdate= new DateTime(1980,11,03).Date
            };

            manager.Create(user, "superAdmin@Pass!");
            //managing admin roles
            if (roleManager.Roles.Count() == 0)
            {
                roleManager.Create(new IdentityRole { Name = "SuperAdmin" });
                roleManager.Create(new IdentityRole { Name = "Admin" });
                roleManager.Create(new IdentityRole { Name = "User" });
            }

            var adminUser = manager.FindByName("superAdmin");

            manager.AddToRoles(adminUser.Id, new string[] { "SuperAdmin", "Admin" });
            if (context.Clients.Count() > 0)
            {
                return;
            }

            context.Clients.AddRange(BuildClientsList());
            context.SaveChanges();

        }

        private static List<Client> BuildClientsList()
        {

            List<Client> ClientsList = new List<Client>
            {
                new Client
                { Id = "ngAuthApp",
                    Secret= Helper.GetHash("abc@123"),
                    Name="Front-end Application",
                    ApplicationType =  Models.ApplicationTypes.JavaScript,
                    Active = true,
                    RefreshTokenLifeTime = 7200,
                    AllowedOrigin = "http://localhost:55146"
                },
                new Client
                { Id = "consoleApp",
                    Secret=Helper.GetHash("123@abc"),
                    Name="Console Application",
                    ApplicationType =Models.ApplicationTypes.NativeConfidential,
                    Active = true,
                    RefreshTokenLifeTime = 14400,
                    AllowedOrigin = "*"
                }
            };

            return ClientsList;
        }
    }
}
