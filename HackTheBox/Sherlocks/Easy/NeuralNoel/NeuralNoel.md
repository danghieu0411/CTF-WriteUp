# Neural Noel

![](logo.png)

## Sherlock scenario

Santa's North Pole Operations is developing an AI chatbot to handle the overwhelming volume of messages, gift requests, and communications from children worldwide during the holiday season. The AI system is designed to process these requests efficiently and provide support in case of any issues.

As Christmas approaches, Santa's IT team observes unusual activity in the AI system. Suspicious files are being accessed, and the system is making unusual HTTP traffic. Additionally, the customer service department has reported strange and unexpected requests coming through the automated AI chatbot, raising the need for further investigation.

## Given artefacts

Packet capture file and linux logs

## Questions

### 1. What username did the attacker query the AI chatbot to check for its existence?

Initial inspection of the pcap shows that this is a webserver hosting a kind of stupid AI with multiple options:

![](1.png)

User picks RAG chatbot first, after initial greeting and the chatbot mentions the name Juliet, user immediate asks whether Juliet is also a username:

![](2.png)

**Answer: Juliet**

### 2. Which AI chatbot did the attacker attempt to manipulate into revealing data stored on its server?

Then he moves to the next chatbot option, trying to lure it to give all data:

![](3.png)

**Answer: GDPR Chatbot**

### 3. On which server is the AI chatbot hosted?

Any HTTP response header would contain this information:

![](4.png)

**Answer: Werkzeug/3.1.3 Python/3.12.7**

### 4. Which AI chatbot disclosed to the attacker that it could assist in viewing webpage content and files stored on the server?

![](5.png)

**Answer: Web & Files Chatbot**

### 5. Which file exposed user credentials to the attacker?

![](6.png)

**Answer: creds.txt**

### 6. What time did the attacker use the exposed credentials to log in?

Use auth.log:

![](7.png)

**Answer: 06:49:44**

### 7. Which CVE was exploited by the attacker to escalate privileges?

Look at the bash history:

![](8.png)

This matches the PoC of [CVE-2023-44467](https://security.snyk.io/vuln/SNYK-PYTHON-LANGCHAIN-6041516), a `langchain`'s vulnerability that may lead to arbitrary RCE:

![](9.png)

**Answer: CVE-2023-44467**

### 8. Which missing command execution function in the Python library led to the exploitation of the above vulnerability?

Follow the reference about the github commit used to patch the CVE:

![](10.png)

They omit `__import__` keyword in their blacklist!

**Answer: `__import__`**

### 9. What time did the attacker successfully execute commands with root privileges?

Croess-reference `auth.log`:

![](11.png)

**Answer: 06:56:41**