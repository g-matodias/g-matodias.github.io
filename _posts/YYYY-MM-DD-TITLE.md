---
title: TITLE
date: YYYY-MM-DD
categories: [TOP_CATEGORY, SUB_CATEGORY]
tags: [TAG]		#TAG names should always be lowercase
---

For this lab we will be utilizing the files Lab01-01.exe and Lab01-01.dll located on our FlareVM machine at C:\Users\FlareVM\Desktop\Tools

Tools I will be using for this lab: PEid, PEviewer, Dependancy Walker, Strings

Lab 1-1:

1. Upload the files to https://www.virustotal.com and view the reports. Does this file match any existing antivirus signatures?

	The FlareVM setup I am running is completely isolated from the internet so I pulled the hashes from PEviewer.

	Lab01-01.exe

	290934c61de9176ad682ffdd65f0a669
	f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba
	Lab01-01.dll MD5: bb7425b82141a1c0f7d60e5106676bb1 SHA256: 58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47

2. When were these files compiled?

3. Are there any indications that either of these files are packed or obfuscated? If so, what are the indicators?

4. Do any imports hint at what this malware does? If so, which imports are they?

5. Are there any host based indicators that you could look for on infected systems?

6. What network-based indicators could be used to find this malware on infected machines?

7. What would you guess is the purpose of these files?
