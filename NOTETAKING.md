Deliverables:
uncontrolled unknown env, note taking during the test
repeatability of the test: real issue, actual fix
if sys fail, find out what exactly happened.

follow RoE, RoE need to be very clear

testing might be because of regulatory compliance: must follow OWASP Penetration Teesting Execution Standard: https://owasp.org/www-project-web-security-testing-guide/latest/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies

Note Portability: just have everything in md and ready to be hand over in case of emergency

General Structure:
concise and precise
record exactly what we did
every command, every mod code, where we clicked on the GUI (reproduce action)
structured and sufficently detailed to remove ambiguity
provide suffucent technical details for good report later
coherent note taking

Application name: muti app test, natural folder and file struct
URL
Request Type: HTTP repoest GET, POST, manual change to the request such as POST request message (MITM)
Issue Detail: overview of vulnerability that will be triggered by actions, point to CVE, explain impact observed, categorize as DoS, remote code exe, privesc
PoC payload: string or code block that'll trigger the vulnerability. most important. list all necessary preconditions and provide exact code or commands that would need to be used

Tooling:
screenshots: if there's alot consider inline insertaion of shots
code block: formatted proerly and quickly understood
portability: cross-OS, easy to transer (pdf)
directory structure: see appname

(suggested sublime/cherry tree(std::kali)/obsidian md editor)

screenshoting:
good: 
only one concept at a time
legible
visual indication that applies to client
material that's described
supports description
framing

bad:
illegible
generic
obfuscated or irrelevant info
not framed proerly

tools:
prtsc




purpose of a report: to deliver value
understand: purpose of the report & how can we deliver the info in a way that's understandable

path forward that oulines flaws in system defined by the RoE, ways to fix in an immediate sense and goals that will prevent vulnerabilities from appearing in the furture. (report is the only thing that matters, see OWASP Pentest guides)

what happens when no vulnerability is found:
if nothing is there don't be too technical, simple statement is good enough (talk to clients about prefernce)

understand client's bussiness goals and objectives (RoE)

client specific key areas to highlight: HIPPA, PCI (compliance)

context matters: HTTP cleat text logon (internal v external)

present useful accurate actionable info without bias

Skill appropriate content for all reader of report, executives, head of security, technicl memders ect

splitting up content into appropriate structure of sections and subsections. most important level of client is normally management

Executive summary: first section, senior management to understand scope and outcome at a sufficient level to understand value of test
quick bite sized pieces of info that provide big picture 

ouline scope, what was tested, if anything is dropped from the scope, timing issue, insuddicient testing time due to finding too many vulnerabilities to report on. for own protection

time frame of the test, len of time on testing, date, testing hours

RoE and referee report

supporting infrastructure and accounts

for example:
Executive Summary:

- Scope: https://kali.org/login.php
- Timeframe: Jan 3 - 5, 2022
- OWASP/PCI Testing methodology was used
- Social engineering and DoS testing were not in scope
- No testing accounts were given; testing was black box from an external IP address
- All tests were run from 192.168.1.2

long form executive summary:
summary of test for high level overview of each step of the engagement and establish severity, context and a worst case scenario for key findings. no bias

note trends for strategic advice, group findings with similar vulnerabilities, XSS, SQLi & file upload: input validation
inform client of system failure here

useful to mention things client has done well, management is paying but working relations is with the tech team

exe sum: sentence for engagment: - "The Client hired OffSec to conduct a penetration test of
their kali.org web application in October of 2025. The test was conducted
from a remote IP between the hours of 9 AM and 5 PM, with no users
provided by the Client."

effective hardening observed:
- "The application had many forms of hardening in place. First, OffSec was unable to upload malicious files due to the strong filtering
in place. OffSec was also unable to brute force user accounts
because of the robust lockout policy in place. Finally, the strong
password policy made trivial password attacks unlikely to succeed.
This points to a commendable culture of user account protections."

discussion of the vulnerabilities:
- "However, there were still areas of concern within the application.
OffSec was able to inject arbitrary JavaScript into the browser of
an unwitting victim that would then be run in the context of that
victim. In conjunction with the username enumeration on the login
field, there seems to be a trend of unsanitized user input compounded
by verbose error messages being returned to the user. This can lead
to some impactful issues, such as password or session stealing. It is
recommended that all input and error messages that are returned to the
user be sanitized and made generic to prevent this class of issue from
cropping up."

engagement wrap-up:
"These vulnerabilities and their remediations are described in more
detail below. Should any questions arise, OffSec is happy
to provide further advice and remediation help."



testing env considerations:
first section: any issue that affected testing, inform all circumstances and limitation of the engagement, improve upon next iteration

positive: "There were no limitations or extenuating circumstances in the engagement. The time allocated was sufficient to thoroughly test the environment."

Neutral: "There were no credentials allocated to the tester in the first two days of the test. However, the attack surface was much smaller than anticipated. Therefore, this did not have an impact on the overall test. OffSec recommends that communication of credentials occurs immediately before the engagement begins for future contracts, so that we can provide as much testing as possible within the allotted time."

Negative: "There was not enough time allocated to this engagement to conduct a thorough review of the application, and the scope became much larger than expected. It is recommended that more time is allocated to future engagements to provide more comprehensive coverage."

technical summary:
key findings, sum and recommendation to the tech team
User and Privilege Management
Architecture
Authorization
Patch Management
Integrity and Signatures
Authentication
Access Control
Audit, Log Management and Monitoring
Traffic and Data Encryption
Security Misconfigurations

4. Patch Management
Windows and Ubuntu operating systems that are not up to date were
identified. These are shown to be vulnerable to publicly-available
exploits and could result in malicious execution of code, theft
of sensitive information, or cause denial of services which may
impact the infrastructure. Using outdated applications increases the
possibility of an intruder gaining unauthorized access by exploiting
known vulnerabilities. Patch management ought to be improved and
updates should be applied in conjunction with change management.

finish with risk map

technical finding and recommendation: 
no need to deep dive, table with ref, risk (H,M,L), issue and recommendations

severity of issue is not context specific bussiness risk, only represents technical severity

findings description with a sentence or two describing what the vulnerability is, why it is dangerous, and what an attacker can accomplish with it. This can be written in such a way to provide insight into the immediate impact of an attack.

and then add details about vulnerability: what vulnerability it is and how to exploit it.

evidence of exploitablility


Appendices furthur info and reference:
what doesn't fit in the above goes here
more insights on not really relavent details

