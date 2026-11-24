WATER GO | XAMPP SETUP

Run PHP 8.2 or newer with PDO MySQL, mbstring, OpenSSL and Argon2id enabled.

1. Start Apache and MariaDB in XAMPP. For a fresh database, import database.sql.
   It creates the app tables and synthetic customer, product and order rows.
   For an existing database, back it up. Apply the prior profile and security
   monitoring migrations if their tables are missing, then import
   handout_security_migration.sql in the water_go database. You can re-run the
   handout migration on XAMPP MariaDB. Preserve existing account IDs. New
   registrations use xxxx-xxxx.
2. Install PHPMailer by running composer install in this directory.
3. When the private config does not exist, copy config.sample.php to
   C:\xampp\water_go_config.php, outside Apache's document root. Fill in database,
   SMTP, reCAPTCHA and encryption settings. Set base_url to the actual site URL.
   For another install path set WATER_GO_CONFIG_FILE to an absolute path outside
   the document root. PHP must be able to read that file and write the external
   error log. Use a scoped database account instead of root for a shared site.
   Generate a 32-byte encryption key in a private terminal:
     C:\xampp\php\php.exe -r "echo base64_encode(random_bytes(32)), PHP_EOL;"
   Store the key only in the private config and keep a secure backup. For Gmail
   supply an app password. For instructor-approved Mailpit, set the SMTP host
   and port, leave username/password/encryption empty, and set a valid sender.
4. For an existing database, convert legacy emergency contacts after the
   encryption key is configured:
     C:\xampp\php\php.exe -r "require 'config/database.php'; require 'includes/profile_validation.php'; echo registration_encrypt_existing_contacts(`$pdo), PHP_EOL;"
5. Provision one admin from PowerShell using a mailbox you can access. Set
   WATER_GO_ADMIN_NAME, WATER_GO_ADMIN_USERNAME, WATER_GO_ADMIN_EMAIL and WATER_GO_ADMIN_PASSWORD
   in that terminal and run:
     C:\xampp\php\php.exe scripts/create_admin.php
   The admin signs in with the provisioned username and password. Use the first
   email OTP to access Settings > Authenticator app and enroll a time-based code
   generator. After enrollment, admin sign-ins require app codes. Keep the
   mailbox accessible for alerts and password recovery.
   For an existing database, apply admin_recovery_migration.sql, login_otp_cooldown_migration.sql and
   admin_authenticator_migration.sql. Set a unique admin_username for each
   already-provisioned admin (avoid usernames used in staff profiles). After
   signing in, open Recovery questions and save three questions and answers.
   Create two demo staff accounts using public registration
   and inboxes you control. Keep credentials in your private demo notes.
6. Open http://localhost/water_go/. Send a registration or sign-in code to your
   own inbox as the Checkpoint 1 mail test.

SHARED SETTINGS

Username 6 to 20 characters, starting with a letter, using letters and digits.
Password 8 to 64 characters and at least Medium. Names limited to 50 characters.
Choose three distinct questions from Q1 to Q8. Forgot Password is always visible on the sign-in form. Three failures per tier lock the identifier for
15, 30 and 60 seconds, respectively. Later groups of three use 60 seconds.
Ten failures from one IP within ten minutes block the IP for 60 seconds.
OTP expiry is five minutes. Each code allows three wrong entries. Resend waits
60 seconds and allows at most three resends within 15 minutes. Sessions expire
after 60 idle seconds and display a warning 10 seconds before expiry.

MONITORING

Run the report from PowerShell:
  C:\xampp\php\php.exe -r "require 'includes/session_security.php'; require 'config/database.php'; auth_run_monitor(`$pdo);"
The admin dashboard is read-only and polls its authenticated JSON endpoint every
60 seconds. The report scans 24 hours and writes one daily flag per pattern and
target. Its PHP entry point is CLI-only and returns 404 over HTTP. This
workspace denied the handout path scripts/monitor.php, so use the command above.
For a 15-minute schedule, create a Windows Task Scheduler trigger that repeats
every 15 minutes indefinitely. Use C:\xampp\php\php.exe as the program,
-r "require 'includes/session_security.php'; require 'config/database.php'; auth_run_monitor($pdo);" as the arguments, and
C:\xampp\htdocs\water_go as Start in. Run it manually for the demo.

HANDOUT MATERIALS

Read handout_documents.txt for the proposal draft, design decisions, privacy
note, threat model and journal template. See registration_validation_messages.md
for exact validation text. The instructor signs the proposal at Checkpoint 1.
Record actual checkpoint dates, a delivered test email, actual weekly entries
and commits in your own repository. Keep real inbox credentials private.
