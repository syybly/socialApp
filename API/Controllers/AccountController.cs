using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDTO>> Register(RegisterDTO registerDTO) {
            if(await UserExists(registerDTO.Username)){
                return BadRequest("Username is taken!");
            }
            using var hamc = new HMACSHA512();
            var user = new AppUser {
                UserName = registerDTO.Username.ToLower(),
                PasswordHash = hamc.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
                PasswordSalts = hamc.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDTO {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

       
        [HttpPost("login")]
        public async Task<ActionResult<UserDTO>> Login(LoginDTO loginDTO) {
            var user = await  _context.Users
            .SingleOrDefaultAsync(x => x.UserName == loginDTO.Username);

            if(user == null) {
                return Unauthorized("Invaild username!");
            }

            using var hamc = new HMACSHA512(user.PasswordSalts);
            var computeHash = hamc.ComputeHash(Encoding.UTF8.GetBytes(loginDTO.Password));
            for (int i=0; i<computeHash.Length; i++) {
                if(computeHash[i] != user.PasswordHash[i]) {
                    return Unauthorized("Invalid password!");
                 }
            }
            
            return new UserDTO {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
           
           
        }

        private async Task<bool> UserExists(string username){
            return await _context.Users.AnyAsync(x=> x.UserName == username.ToLower());
        }
    }
}