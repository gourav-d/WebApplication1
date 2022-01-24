using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace WebApplication1
{
	public class HomeController : Controller
	{
		[Authorize]
		public async Task<IActionResult> Index()
		{

			try
			{
				//this.HttpContext.GetTokenAsync();
			}
			catch (Exception e)
			{

			}

			await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, HttpContext.User);

			return View();
		}

		public async Task<IActionResult> T()
		{

			string key = "my_secret_key_12345"; //Secret key which will be used later during validation    
			var issuer = "http://mysite.com";  //normally this will be your site URL    

			var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
			var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

			//Create a List of Claims, Keep claims name short    
			var permClaims = new List<Claim>();
			permClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
			permClaims.Add(new Claim("valid", "1"));
			permClaims.Add(new Claim("userid", "1"));
			permClaims.Add(new Claim("name", "bilal"));

			//Create Security Token object by giving required parameters    
			var token = new JwtSecurityToken(issuer, //Issure    
							issuer,  //Audience    
							permClaims,
							expires: DateTime.Now.AddDays(1),
							signingCredentials: credentials);
			var jwt_token = new JwtSecurityTokenHandler().WriteToken(token);

			//Valid Token

			//Token

			
			

			//Response.Cookies.Append("X-Access-Token", jwt_token, new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Strict });
			//Response.Cookies.Append("X-Username", "bittu", new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Strict });
			//Response.Cookies.Append("X-Refresh-Token", jwt_token, new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Strict });

			var identity = new ClaimsPrincipal(new ClaimsIdentity(token.Claims));

			//await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, identity);

			//Lets = Token = Abc
			//Store in In-Memory Cache - >
			//	Dictimory =
			//Key - UID
			//Value - Token - {refrsh, token, rxpiry}

			//Call the API to get user basic info...first name, lastname etc...userId --optional
			//
			//Custom claims 
			// UID is also part of claims
			
			//Will generate the Cookies using claims
			//Send the cookies 
		

			var persistent = false;
			var claimsIdentity = new ClaimsIdentity(permClaims,CookieAuthenticationDefaults.AuthenticationScheme);

			Response.Cookies.Append("Gourav", "Some Data in cookies");


			await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
				new ClaimsPrincipal(claimsIdentity),
				new AuthenticationProperties
				{
					ExpiresUtc = false ? null : (DateTimeOffset?)DateTimeOffset.MinValue,
					IsPersistent = false
				});

			if (!persistent)
			{
				// Don't even send out a cookie even if it's expired from the start
				HttpContext.Response.Headers.Remove("Set-Cookie");
			}

			HttpContext.User = new ClaimsPrincipal(claimsIdentity);

			await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, HttpContext.User);

			return View("T");
		}
	}
}
