# Registration Validation Message Mapping (P6)

The server validates every submitted value. Client-side checks are for immediate feedback only; they do not replace server validation.

| Field / rule | Message shown |
|---|---|
| CSRF token is missing or expired | Your session expired. Reload the page and try again. |
| Login CSRF token is missing or expired | Your sign-in form expired. Reload the page and try again. |
| Login credentials do not match | Invalid username or password. |
| Login identifier has reached the next lockout tier | Too many failed sign-in attempts. A separate timer shows the remaining seconds. |
| ID Number is empty | ID Number is required. |
| ID Number is not 4 digits, a hyphen, then 4 digits | ID Number must follow the format xxxx-xxxx. |
| ID Number already exists | This ID Number is already registered. |
| Username is empty | Username is required. |
| Username is empty, outside 6–20 characters, does not start with a letter, or contains characters other than letters and digits | Username must start with a letter and use 6–20 letters or numbers. |
| Username is already taken | This username is already registered. |
| Username availability cannot be checked | Username availability could not be checked. |
| First Name is empty | First Name is required. |
| Middle Name contains a value but violates a name rule | The applicable Middle Name rule message below is shown. |
| Last Name is empty | Last Name is required. |
| Name contains digits | Numbers are not allowed in [Field]. |
| Name contains punctuation or other special characters | Special characters are not allowed in [Field]. |
| Name contains consecutive spaces | Double space is not allowed. |
| Name contains three identical letters in sequence | Three consecutive identical letters are not allowed. |
| Name is all uppercase | Do not use all capital letters. |
| Name is fewer than 2 or more than 50 characters | [Field] must be between 2 and 50 characters. |
| Name is not Title Case | First letter of your name must be capital. |
| Name Extension has an unsupported selection | Choose Jr., Sr., or Other for Name Extension. |
| Other Name Extension is not exactly I, II, III, IV, IX, or X | Name Extension must be I, II, III, IV, IX, or X. |
| Combined name exceeds 500 characters | Your combined name must be 500 characters or fewer. |
| Email is empty | Email is required. |
| Email contains whitespace | Email must not contain spaces. |
| Email is longer than 100 characters | Email must be 100 characters or fewer. |
| Email format is invalid | Please enter a valid email address. |
| Email is already registered | This email is already registered. |
| Emergency Contact Number is not exactly 11 digits beginning with 09 | Contact number must be 11 digits and start with 09. |
| Birthdate is empty | Birthdate is required. |
| Birthdate is not a real date | Enter a valid birthdate. |
| Birthdate is in the future | Birthdate cannot be in the future. |
| Calculated age is under 18 | You must be at least 18 years old to register. |
| Purok / Street is empty | Purok / Street is required. |
| Purok / Street contains consecutive spaces | Double space is not allowed in Purok / Street. |
| Purok / Street contains characters other than letters, digits, or spaces | Purok / Street may contain only letters, numbers, and spaces. |
| Purok / Street is not 2–50 characters | Purok / Street must be between 2 and 50 characters. |
| Barangay, Municipality / City, Province, or Country is empty | [Field] is required. |
| Address name contains digits | Numbers are not allowed in [Field]. |
| Address name contains punctuation or other special characters | Only letters and spaces are allowed in [Field]. |
| Address name contains consecutive spaces | Double space is not allowed in [Field]. |
| Address name is all uppercase | [Field] must not be all capital letters. |
| Barangay, Municipality / City, or Province is not 2–50 characters; Country is not 2–100 characters | [Field] must be between 2 and [maximum] characters. |
| Address name is not Title Case | First letter of each word in [Field] must be capital. |
| ZIP Code is not exactly 4 digits | ZIP Code must be exactly 4 digits. |
| Password is empty | Password is required. |
| Password is shorter than 8 characters | Password must be at least 8 characters. |
| Password is longer than 64 characters | Password must be 64 characters or fewer. |
| Password strength is Weak | Password is weak. Use at least 8 characters and mix at least two character types. |
| Re-entered password does not match | Passwords do not match. |
| Three security questions are not selected or are not different | Choose three different security questions from the list. |
| A security answer is empty | Security answer [1, 2, or 3] is required. |
| A security answer contains consecutive spaces | Double space is not allowed in Security answer [1, 2, or 3]. |
| A security answer contains characters other than letters or spaces | Security answer [1, 2, or 3] may contain only letters and spaces. |
| A security answer is not 2–50 characters | Security answer [1, 2, or 3] must be between 2 and 50 characters. |
| Privacy consent checkbox is not checked | You must agree to the Privacy Notice to register. |
| Forgot-password identifier is empty | Enter your username. |
| Forgot-password request CSRF token is missing or expired | Reload this page and try again. |
| OTP is wrong, expired, used, or has reached 3 attempts | The OTP is invalid, expired, or has already been used. |
| Password change CSRF token is missing or expired | Reload the form and try again. |
| Recovery answers differ | Answers do not match. |
| Submitted security answer does not verify | The security answer could not be verified. |
| Password change confirmation differs | Mismatch Password. |
| Password change input is shorter than 8 or longer than 64 characters | Password must contain 8 to 64 characters. |
| Password was used recently | You cannot reuse a recent password. |
| Authenticated session has been idle for 60 seconds | Your session expired due to inactivity. Please sign in again. |

[Field] is replaced with the field name shown on the form; bracketed seconds are calculated from the active lockout window. Browser username feedback also uses “Checking username availability…”, “Username is available.”, and “This username is already registered.” A weak password shows “Password strength: Weak. Use at least 8 characters and mix at least two character types.” The shared authentication settings are listed in README.txt.
