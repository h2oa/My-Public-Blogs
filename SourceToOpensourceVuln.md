This is a CTF challenge at my old company, based on a real world Red Team project.

# Reconnaissance

The provided target doesn't have any function, feature, just like a landing page. Even the fuzzing path, do anything doesn't reveal any additional endpoints or expose any secrets.

From some keywords in the HTML source code, search through Github found some projects with similar keyword.

<img width="1697" height="925" alt="{6F45AAB7-FB18-4C95-8FC9-7256E1322A73}" src="https://github.com/user-attachments/assets/703d8999-c07a-4638-a265-ca4a55546531" />

In this case, the web program language is PHP -> To determine if the original source code is relevant, simply create a list of PHP paths (found from the GitHub source) and fuzz the original website's URL:

- If the PHP path exists, will get a blank page or the code content.
- If the path does not exist, will get a 404 not found error.

<img width="802" height="273" alt="{A3C8347E-2172-4E2F-B395-EA9F04CB3471}" src="https://github.com/user-attachments/assets/a12ee681-5cd3-4a9a-964f-86d4b01e5c67" />

Through the publicly available source code, I discovered the website had an admin login endpoint at ``, but I focused on finding unauth SQL injection vulnerabilities.

<img width="1266" height="412" alt="image" src="https://github.com/user-attachments/assets/a44e4304-38dd-4ab7-8ae4-d7874ccbec0f" />

Ultimately, nothing could be extracted, I got the hint from challenge author that need to brute force the admin account.

Generate password wordlist: https://github.com/pannagkumaar/P-Gen

In the admin dashboard:

- The interface has an input field that allows to enter the path to the image file to display on the screen, but it must be in a static folder.
- File uploads can exploit path traversal.
- Reading images uses several file-reading functions such as file_exist, file_get_contents, etc.

This function allows control prefix protocol, so with the path traversal, enabling file uploads to any desired folder -> phar php upload

<img width="653" height="90" alt="image" src="https://github.com/user-attachments/assets/78bc07a4-58b3-45e4-a4ee-b618ae07e387" />
