This is a website of a school for store students' file, use DSpace open source but not in latest version. After analysis the open source code, I found a 0day vulnerability (not in the public CVEs list)

# Reconnaissance

From the HTML source code, I can easily determine the website use DSpace open source project:

<img width="1584" height="386" alt="{21B3A2AF-4B48-48CD-9A26-2C5E9515AAF3}" src="https://github.com/user-attachments/assets/e7f5ce55-38e3-47e2-b3ac-1d8588d03f96" />

The reset password feature of the target website return the different messages when the user input email exist and non-exist in database. So I can use this signal to enumerate some exist email:

<img width="889" height="305" alt="image" src="https://github.com/user-attachments/assets/aadaa52e-1724-4dca-b288-a7c1186f276f" />

At the same time, the login function has no rate limit, allowing attackers to brute-force passwords, after some tries, I got an account.

<img width="1046" height="408" alt="image" src="https://github.com/user-attachments/assets/892ad7c0-8629-408b-8598-c4439ac7daa6" />

Now I can analysis the DSpace open source code, any vulnerability in unauth or auth type I can use to exploit.

# Analysis DSpace

By searching for several publicly available CVEs on the internet, an attacker can upload HTML files to a website, leading to XSS exploitation

<img width="830" height="159" alt="image" src="https://github.com/user-attachments/assets/5caacb6e-7836-450a-8db3-8feb627e1a2c" />

I attempted to analyze the source code and discovered another critical vulnerability, in addition to the published CVE vulnerabilities, DSpace version 6.3 allows low-privilege users to delete any file on the system via the file upload function at the /jspui/submit endpoint.

(https://github.com/DSpace/DSpace/blob/813800ce1736ec503fdcfbee4d86de836788f87c/dspace-jspui/src/main/java/org/dspace/app/webui/servlet/SubmissionController.java#L1589)

<img width="1366" height="392" alt="{FB1971C3-D8BD-48CC-A402-5CD006E6FBC5}" src="https://github.com/user-attachments/assets/08f192ef-d8c9-4a55-ab80-c16b16d23020" />

The DoGetResumable function does not clean up the user-passed parameter value (resumableChunkNumber), but uses it directly as the file extension. The function then checks if the file exists and if its length matches resumableCurrentChunkSize; if not, the file is deleted.

<img width="1359" height="686" alt="{9C57EBF8-4CDE-4442-A505-137AF704A7F0}" src="https://github.com/user-attachments/assets/28c5161a-2902-4c5b-8923-4c86bd1bca79" />

Therefore, an attacker can exploit this function by passing data in the format `/../../../../../../../../../../../../../../dspace/webapps/jspui/static/js/scriptaculous/builder.js` (webroot obtained from the application's stack trace) to the resumableChunkNumber param in order to delete the builder.js file.
