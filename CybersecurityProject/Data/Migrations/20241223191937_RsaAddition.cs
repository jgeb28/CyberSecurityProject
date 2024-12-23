using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CybersecurityProject.Data.Migrations
{
    /// <inheritdoc />
    public partial class RsaAddition : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "RsaPrivateKeyEncrypted",
                table: "AspNetUsers",
                type: "TEXT",
                maxLength: 5000,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "RsaPublicKey",
                table: "AspNetUsers",
                type: "TEXT",
                maxLength: 5000,
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RsaPrivateKeyEncrypted",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "RsaPublicKey",
                table: "AspNetUsers");
        }
    }
}
