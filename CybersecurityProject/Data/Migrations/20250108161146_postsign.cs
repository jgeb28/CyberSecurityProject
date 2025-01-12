using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CybersecurityProject.Data.Migrations
{
    /// <inheritdoc />
    public partial class postsign : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsVerified",
                table: "Posts",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "RsaSignature",
                table: "Posts",
                type: "TEXT",
                maxLength: 3000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsVerified",
                table: "Posts");

            migrationBuilder.DropColumn(
                name: "RsaSignature",
                table: "Posts");
        }
    }
}
