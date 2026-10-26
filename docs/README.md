# PHP/XAMPP Movie Stream Demo

Place the `php_app` folder into your XAMPP `htdocs` directory (e.g., `C:\xampp\htdocs\php_app`).

Steps:

1. Start XAMPP: open XAMPP Control Panel and start Apache.
2. Open a browser to: http://localhost/php_app/
3. Seed the DB once by visiting: http://localhost/php_app/seed.php (this creates an `admin` and `user` account)

Composer dependencies (PHPMailer, WebAuthn library)

1. From the `php_app` folder run:

```
composer install
```

2. Configure SMTP settings in `config.php` to enable real email sending.

WebAuthn (biometrics) notes

- WebAuthn requires HTTPS (localhost with XAMPP: enable SSL or use `https://localhost` with proper cert).
- The demo includes endpoints that generate challenges and store credentials, but full cryptographic verification requires the `web-auth/webauthn-lib` package and proper configuration. After running `composer install`, the demo will detect the library and you can complete server-side verification.

MySQL (XAMPP) integration

- To use MySQL instead of SQLite, edit `config.php` and set `mysql.enabled = true`, and provide `host`, `database`, `user`, and `pass`.
- Create the database using phpMyAdmin or the MySQL CLI, then run `seed.php` to populate users.


Seeded credentials:
- Admin: `admin` / `AdminPass123!`
- User: `user` / `UserPass123!`

Notes:
- This demo uses SQLite (`database.sqlite` generated in the folder).
- OTPs are not actually emailed — they appear as a preview on the register page for demo purposes.
- For production, replace the OTP preview with real email sending (PHPMailer) and secure the app.
