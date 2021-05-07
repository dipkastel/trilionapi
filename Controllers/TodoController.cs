using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using trilionapi.Data;
using trilionapi.Models;

namespace trilionapi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class TodoController : ControllerBase
    {
        private readonly ApiDbContext _context;

        public TodoController(ApiDbContext context) {
            this._context = context;
        }


        [HttpGet]
        public async Task<IActionResult> GetItems()
        {
            var items = await _context.Items.ToListAsync();
            return Ok(items);
        }

        [HttpPost]
        public async Task<IActionResult> CreateItem(ItemData data) {
            if (ModelState.IsValid)
            {
                await _context.Items.AddAsync(data);
                await _context.SaveChangesAsync();

                return CreatedAtAction("GetItem", new { data.Id }, data);

            }

            return new JsonResult("something went wrong") { StatusCode=500};

        
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetItem(int id) {
            var item = await _context.Items.FirstOrDefaultAsync(p => p.Id.Equals(id));
            if (item == null)
                return NotFound();
            return Ok(item);
        
        
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateItem(int id,ItemData item)
        {
            if (id != item.Id)
                return BadRequest();
            var existItem = await _context.Items.FirstOrDefaultAsync(x => x.Id.Equals(id));
            if (existItem == null)
                return NotFound();
            existItem.Title = item.Title;
            existItem.Description = item.Description;
            existItem.Done = item.Done;

            await _context.SaveChangesAsync();

            return NoContent();


        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteItem(int id)
        {
            var existItem = await _context.Items.FirstOrDefaultAsync(x => x.Id.Equals(id));
            if (existItem == null)
                return NotFound();

            _context.Items.Remove(existItem);
            await _context.SaveChangesAsync();

            return Ok(existItem);


        }
    }
}
