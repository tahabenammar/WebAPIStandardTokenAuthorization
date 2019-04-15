using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace TokenAuthentication.API.Controllers
{
    [Authorize]
    [RoutePrefix("api/values")]
    public class ValuesController : ApiController
    {
        [Route("")]
        public IHttpActionResult Get()
        {
            return Ok(new { value1=1,value2=2});
        }
    }
}
