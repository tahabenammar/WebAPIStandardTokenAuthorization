using Microsoft.AspNet.Identity;
using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using System.Web;

namespace TokenAuthentication.API.Services
{
    public class IdentityEmailService : IIdentityMessageService
    {
        public async Task SendAsync(IdentityMessage message)
        {
            await SendEmailAsync(message);
        }

        // Use NuGet to install SendGrid (Basic C# client lib) 
        private async Task SendEmailAsync(IdentityMessage message)
        {
            var myMessage = new SendGridMessage();
            myMessage.AddTo(message.Destination);
            myMessage.Subject = message.Subject;
            myMessage.PlainTextContent = message.Body;
            myMessage.HtmlContent = message.Body;
            await SendGridMailing.SendEmail(myMessage);

        }
    }
}