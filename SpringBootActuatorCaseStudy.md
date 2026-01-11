This article document a real world case study in exploiting the Spring Boot Actuator path leak, analysis the heapdump file and take over the admin account in two different methods.

# Reconnaissance

The target company develop a mobile application for staffs to book elevator. By capture request in the mobile application, I got the host that called from client when ever user book elevator. This host has a subdomain string is the name of company building (For security reason, I called it `specialpark.target.com`), this keyword `specialpark` is not in my wordlist (may be not in every public wordlists) - that's the reason why this subdomain can't appear in my subdomain fuzzing result for `target.com`.

When I open this subdomain in browser, it has a login form, require a staff Active Directory account to login.

From result of Wappalyzer, front end server use ReactJS, maybe I can crawl some interesting endpoints from Javascript files.

<img width="617" height="359" alt="{2E2E2E7E-E282-427A-83D2-174E9B67B7E3}" src="https://github.com/user-attachments/assets/712b57d3-6e14-4ff5-9d42-13eb5872a1eb" />

<img width="900" height="451" alt="image" src="https://github.com/user-attachments/assets/b8f68e65-a346-4118-b36f-af06201b1772" />

Base on my experience, I started fuzzing with all these paths `/sap/`, `/sap/api/`, `/sap/api/v0/`, `/iam/`, `/iam/api/`, `/iam/api/v0/`, ... to find some interesting endpoint. I observed that when the keyword `actuator` appear in path, response return a 403 error.

<img width="992" height="198" alt="image" src="https://github.com/user-attachments/assets/1a6a25a0-e597-47af-ae70-821e93aefa31" />

# Bypass nginx block rule

This is a rule block in nginx, maybe for blocking attacker access to Actuator endpoints in Spring Boot framework. On the other hand, this error message shows that Actuator paths weren't disable, just prevented by the nginx rule.

After some tries, I can bypass this rule by URL encoded, for example `/actuator -> /actuat%6fr`

<img width="1171" height="573" alt="image" src="https://github.com/user-attachments/assets/93891b46-7b3e-4020-8615-cdece7770b09" />

The endpoint `/actuator/env` display all the envirenment value but all sensitive passwords will show in `******` format.

<img width="1182" height="266" alt="image" src="https://github.com/user-attachments/assets/47db54f9-e48a-45c5-ae7a-3aec5b008095" />

Let's download the heapdump file and start analysis `/base-path.../actuat%6f/heapdump`

# Analysis heapdump file

I used VisualVM for analysing the heapdump file.

<img width="1911" height="897" alt="{D09F6D66-8EA7-4D17-B386-D86E15E8476C}" src="https://github.com/user-attachments/assets/bc6b39a8-ba4b-4883-a278-2344dff57d56" />

OQL query (like SQL) used to search strings that include "PASSWORD": `select s.toString() from java.lang.String s where ( s.toString().contains("PASSWORD") )`. Found REDIS_PASSWORD, AND_MEDIA_PASSWORD:

<img width="1133" height="520" alt="image" src="https://github.com/user-attachments/assets/32997ecf-1a7b-450c-8b53-45a9e8098344" />

Website allows access the oauth2 token creator endpoint

<img width="1123" height="471" alt="image" src="https://github.com/user-attachments/assets/7bbf8765-9c26-4542-b493-95ff95ad1a18" />

This endpoint allows a client to obtain an `access_token` on behalf of itself (https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html#oauth2-client-client-credentials). Now I need the value of `COMMON_CLIENT_OAUTH2_CLIENT_ID` and `COMMON_CLIENT_OAUTH2_CLIENT_SECRET`, because the to get the access_token will be in format `base64(str(COMMON_CLIENT_OAUTH2_CLIENT_ID:COMMON_CLIENT_OAUTH2_CLIENT_SECRET))`.

<img width="1361" height="486" alt="image" src="https://github.com/user-attachments/assets/1d5a7832-ec3b-4cc9-bf1e-d94c7cbe0c48" />

Easily create an new access token:

<img width="923" height="434" alt="image" src="https://github.com/user-attachments/assets/d52acde1-c47b-4999-8892-d39c6060c351" />

I also can steal a token just from grep the Cookie or Authorization value log in the heapdump file:

<img width="1265" height="268" alt="image" src="https://github.com/user-attachments/assets/c98e8e83-f981-41ba-8af5-2a0cd5bfc671" />

Add the token in Local Storage, I can access admin dashboard page:

<img width="1262" height="507" alt="image" src="https://github.com/user-attachments/assets/a4ddca37-a8ce-4e7a-a652-edf247ff6a56" />

# Try to develop a tool

Scanning for an actuator path leak simply means fuzzing the path to see if there can access the actuator path.

Advantages:

- Many path scanning/fuzzing tools are available on the internet -> can refer to them.

Disadvantages:

- Actuator paths don't always directly access the root path; they often follow the base path. For example, `/devices-management/actuator/health` -> `/devices-management` is the base path, `/actutator/health` is the actuator fuzzing path -> need to fuzz these base paths first -> temporarily, the idea is to crawl via JavaScript.
- Current tools all fuzz directly using wordlists. For the Viettel bug reported recently, no wordlist contained the complete `/devices-management/actuator/health` path -> need to crawl all the website paths and then fuzz the path using wordlists.
- Not every response is correct; many cases are false positives, such as those encountered during a search. Accessing any path results in a 200 error instead of a 404/403/... -> response analysis is needed.
- The wordlist needs to be compiled and customized based on experience.

https://github.com/h2oa/ActuatorScan

<img width="1416" height="112" alt="{BBF4BC6C-8D68-4FEA-A7A9-79826719DA86}" src="https://github.com/user-attachments/assets/5a5db3cc-85ba-4e1b-9c7b-b6fafcc8da7a" />

# Note

There are other exploitation methods based on the Actuator path leak, maybe I will try later.

Keyword search `Spring Boot Actuator 漏洞利用`

https://github.com/LandGrey/SpringBootVulExploit

https://www.freebuf.com/articles/web/282534.html

https://blog.csdn.net/JHIII/article/details/126601858

https://www.freebuf.com/articles/web/234266.html
