using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace TokenAuthentication.API.Models
{
    public class LinkModel
    {
        public string Href { get; set; }
        public string Rel { get; set; }
        public string Method { get; set; }
        public bool IsTemplated { get; set; }
    }
}