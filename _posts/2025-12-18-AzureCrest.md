---
layout: post
title: 'AzureCrest [Draft]'
categories: KQL KC7
date: 2025-12-19
draft: true
tags: forensics
---

> This is a walkthrough of the KC7 Case "AzureCrest". All questions below are presented in the order of the case unless otherwise specified. **All active links have been defanged with brackets to prevent accidental clicks.**
{: .prompt-info}  

&nbsp;


## Section 1  

### Questions 1-8

#### **Q1: How many employees work at Azure Crest Hospital?**
```
Employees 
| count
```
`250`

&nbsp;


#### **Q2: What is the Chief Financial Officer's name?**

```
Employees
| where role == "Chief Financial Officer"
```
`Penny Pincher`

&nbsp;


#### **Q3: How many distinct senders were seen in the email logs from pharmabest.net?**

```
Email
| where sender has "<Domain Name>"
| distinct <field>
| count
```

`236`

&nbsp;


#### **Q4: How many distinct websites did “Penny Pincher” visit?**

Let's dump the information from Employees here for reference:
```
"hire_date": 2022-01-10T00:00:00.000Z,

"name": Penny Pincher,

"user_agent": Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.96 Safari/537.36,

"ip_addr": 10.10.0.1,

"email_addr": penny_pincher@azurecresthospital.med,

"company_domain": azurecresthospital.med,

"username": pepincher,

"role": Chief Financial Officer,

"hostname": TEX4-MACHINE
```

Fill out the query with the information provided above and the correct operators to get the data we want:
```
OutboundNetworkEvents
| where src_ip == "10.10.0.1"
| distinct url
| count
```

`68`

&nbsp;


#### **Q5: How many distinct domains in the PassiveDns records contain the word “health”?**

```
PassiveDns
| where domain contains "health"
| distinct domain
| count
```

`28`

&nbsp;


#### **Q6: What IPs did the domain “bit.ly” resolve to (enter any one of them)?**

```
PassiveDns
| where domain == "bit.ly"
| distinct ip
```

| ip              |
| --------------- |
| 42.143.126.108  |
| 134.177.143.174 |

&nbsp;


#### **Q7: How many distinct URLs did employees with the first name "Mary" Visit?**

```
let mary_ips =
Employees
| where name has "Mary"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (mary_ips)
| distinct url
| count
```
`119`

&nbsp;


#### **Q8: How many authentication attempts did we see to the accounts of employees with the first name Mary?**

Let's call the variable `mary_auth` for our query:
```
let mary_auth = Employees
| where name has "Mary"
| distinct username;
AuthenticationEvents
| where username in (mary_auth)
| count
```

&nbsp;


## Section 2

### Questions 1-10

#### **Q1: What is the name of the file that was quarantined?**  

We received a security alert a few days ago that a file with the word 'healthcare' was quarantined. We know that it's your first day here, but we get these alerts all the time and they are usually nothing. What could possibly go wrong?

&nbsp;




