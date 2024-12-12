::###############################################################################################################
::
::    Big Belly Baus (www.bigbellybaus.com) Windows 11 Security Hardening Script
::    This script includes hardening for Microsoft 365, Office, Chrome, Adobe Reader, and Microsoft Edge.
::    Read the comments below the command and add the double colon to the start of the line to comment out any code that you don't want or don't feel you need.
::
::###############################################################################################################
::
::    RUN THIS COMMAND MANUALLY BY COPYING AND PASTING INTO COMMAND PROMPT BECAUSE IT DON'T RUN IN A SCRIPT
::
:: FOR /F "usebackq tokens=2 delims=:" %a IN (`sc.exe sdshow scmanager`) DO  sc.exe sdset scmanager D:(D;;GA;;;NU)%a
:: 
:: Breaking down this spell, it looks like you're invoking a powerful loop of sorcery with the FOR /F incantation, which is known for its ability to parse through the ether (or in this case, the output of a command). The sc.exe sdshow scmanager is akin to consulting the ancient tomes to reveal the current security descriptors of the Service Control Manager, which is the heart of managing services in your realm. Now, here's where it gets interesting. With tokens=2 delims=: you're telling your magical assistant (the command line) to pluck out the second piece of knowledge from the tome, using the colon as a signpost to divide the information. The real wizardry happens with sc.exe sdset scmanager D:(D;;GA;;;NU)%a. This incantation is modifying the security descriptor of the SCM. The D:(D;;GA;;;NU) part is particularly intriguing—it's adding a new decree that denies (D) all permissions for the Network Users (NU) group. The %a at the end is where the existing security is only appended.
::###############################################################################################################
:: 
::    ENABLE CONTROLLED FOLDER ACCESS AFTER YOU HAVE EVERYTHING INSTALLED AND TESTED TO MAKE SURE IT WORKS
:: 
:: Open the start menu and type Controlled Folder Access to open the settings.
:: Enabling Controlled Folder Access is like setting elite guards around your most valued digital treasures, offering robust protection against ransomware by blocking unauthorized access to your files. It alerts you to any suspicious attempts to modify your data, allows customization to fit your security needs, and provides peace of mind by safeguarding your most sensitive information without hindering legitimate software operations. It's a strategic defense mechanism for maintaining the integrity and safety of your digital realm.
:: Should a rogue attempt to breach your vaults, Controlled Folder Access will sound the alarm, alerting you to the attempted intrusion. This allows you to respond swiftly, perhaps consulting with your council of mages (IT department) to strengthen any vulnerabilities.
:: If you install new software and you don't want it to be replaced with malicious software, then add the program and/or data folder to the Controlled Folder Access list
::###############################################################################################################
::
::     IF YOU DO NOT USE ANY VIRTUALIZATION SOFTWARE THEN YOU CAN REMOVE THE COMMENTS FROM THESE COMMANDS
:: 
::     Enable Windows Defender Application Guard
::
:: powershell.exe Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard -norestart
::
::     Enable Windows Defender Credential Guard
:: 
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 3 /f
:: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v LsaCfgFlags /t REG_DWORD /d 1 /f
::
::###############################################################################################################
::
::     SCRIPT STARTS HERE
::
powershell.exe enable-computerrestore -drive c:\
:: This enchantment above, when whispered into the ears of your trusty metallic steed (your PC), awakens the ancient guardians known as "System Restore." It basically tells your computer, "Hey buddy, let's keep an eye out and remember how to get back home in case we wander too far into the dark woods (or, you know, if something goes sideways with the system).” It's like having breadcrumbs to find your way back, but without the risk of them being eaten by forest creatures. Quite handy for dodging any sneaky spells cast by those pesky digital witches or the ever-looming specters from the CIA!
:: -------------------------------------------------------------------
powershell.exe vssadmin resize shadowstorage /on=c: /for=c: /maxsize=50000MB
:: This command above is a bit like calling in a favor from the shadowy figures that lurk in the corners of your kingdom. You're basically negotiating with the "Volume Shadow Copy Service" to allocate a slice of your realm (specifically, a chunk of your C: drive) to remember things as they were. With a limit of 50000MB, it's like telling them, "Alright, you can hang around, but don't take up more space than this; we don't want you throwing wild parties and inviting all your shadowy friends over." It's crucial for things like backups and restoring previous states, especially if you suspect the CIA is trying to throw a curse your way.
:: -------------------------------------------------------------------
checkpoint-computer -description "beforewin11hardening"
:: This spell above, my friend, is like telling a wise old wizard to take a snapshot of your castle (your computer, that is) before you start fortifying the walls and sharpening the spears. The "checkpoint-computer" charm is a powerful one, used to create a restore point named "beforewin11hardening." It's like saying, "Remember this moment, O great machine, before we batten down the hatches and prepare for the siege from the invisible foes (you know, those pesky witches and their CIA cronies)."
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v SystemRestorePointCreationFrequency /t REG_DWORD /d 20 /f
:: This spell commands your kingdom's scribes (the Windows Registry) to inscribe a new decree: "SystemRestorePointCreationFrequency." With a value of 20, it dictates that before any new protective spell (a.k.a. system restore point) is cast, there must be at least 20 moon cycles (or in mundane terms, the system will wait for at least 20 events before it considers creating another restore point automatically). This prevents your realm from being cluttered with too many memories of the past, saving space for more important treasures.
:: -------------------------------------------------------------------
powershell.exe -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'BeforeSecurityHardening' -RestorePointType 'MODIFY_SETTINGS'"
:: This powerful command calls upon the spirits of the machine to create a new restore point, dubbed 'BeforeSecurityHardening.' It’s like telling your castle guards to take a good look around and remember exactly how everything is arranged before you start moving the furniture around and boarding up the windows to keep the witches and their spying eyes out. The 'MODIFY_SETTINGS' part ensures that this memory is specifically tied to changes in your kingdom's settings, preparing you for any spells that might backfire during your security hardening rituals.
:: -------------------------------------------------------------------
reg add HKEY_LOCAL_MACHINE\Software\Microsoft\OLE /v EnableDCOM /t REG_SZ /d N /F
:: Here we are delving into the ancient art of disabling the Distributed Component Object Model (DCOM) on your noble steed (a.k.a. your computer). This spell you've concocted is quite the potent one. It whispers to the very core of the machine, telling it to turn off the DCOM feature. DCOM is like a network of magical portals that allow software components to communicate across the land (or in tech speak, across your network).By setting EnableDCOM to N (which stands for "No," as in "No, thank you, we're quite alright without your services, DCOM"), you're effectively closing these portals. This could be a wise move if you're looking to tighten the security of your realm, making it harder for those digital witches and their sneaky familiars (or hackers and malware, to use the common tongue) to move freely about your kingdom.But beware, for while closing these portals can indeed fortify your defenses, it might also hinder the movement of your own allies (current software).
:: Website to check out for the above reg command 
:: https://docs.microsoft.com/en-us/windows/win32/com/enabledcom
:: -------------------------------------------------------------------
assoc .chm=txtfile
assoc .hta=txtfile
assoc .jse=txtfile
assoc .js=txtfile
assoc .vbe=txtfile
assoc .vbs=txtfile
assoc .wsc=txtfile
assoc .wsf=txtfile
assoc .ws=txtfile
assoc .wsh=txtfile
assoc .scr=txtfile
assoc .url=txtfile
assoc .reg=txtfile
assoc .wcx=txtfile
assoc .slk=txtfile
assoc .iqy=txtfile
assoc .prn=txtfile
assoc .diff=txtfile
assoc .deploy=txtfile
assoc .rdg=txtfile
assoc .application=txtfile
:: These assoc commands dabbling in the arcane arts of file type associations. This changes file associations to protect against common ransomware and social engineering attacks. Essentially, you won't be able to click files of this type from Windows, you'll have to run them from powershell or command prompt if you want to use them.
:: Websites to check out for the above assoc commands
:: https://www.trustwave.com/Resources/SpiderLabs-Blog/Firework--Leveraging-Microsoft-Workspaces-in-a-Penetration-Test/
:: https://seclists.org/fulldisclosure/2019/Mar/27
:: https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
:: https://www.trustwave.com/Resources/SpiderLabs-Blog/Firework--Leveraging-Microsoft-Workspaces-in-a-Penetration-Test/
:: https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39
:: https://rinseandrepeatanalysis.blogspot.com/2018/09/dde-downloaders-excel-abuse-and.html
:: https://blog.redxorblue.com/2020/07/one-click-to-compromise-fun-with.html
:: -------------------------------------------------------------------
reg delete "HKLM\SOFTWARE\Classes\.devicemetadata-ms" /f
reg delete "HKLM\SOFTWARE\Classes\.devicemanifest-ms" /f
:: With these spells, you're attempting to erase the very existence of .devicemetadata-ms and .devicemanifest-ms from the annals of your kingdom's lore, stored within HKLM\SOFTWARE\Classes. These files, known in less mystical terms as device metadata and device manifest files, are akin to the scrolls that describe the essence and purpose of various magical artifacts within your realm (or, in the mundane world, they help Windows recognize and work with different hardware devices). Casting reg delete with the /f flag is a bold move, akin to wielding a powerful, unforgiving wand. It forces the deletion without asking any scribe or scholar (or user prompt) for confirmation. It's like saying, "Begone, foul entries, and let the memory of you fade from this realm!"
:: For info on the above 2 reg delete commands see https://posts.specterops.io/remote-code-execution-via-path-traversal-in-the-device-metadata-authoring-wizard-a0d5839fc54f
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f
:: This incantation, when cast, ventures into the heart of your realm's laws, inscribed within HKLM\SOFTWARE\Policies\Microsoft\Windows\System. It conjures a new decree named DontDisplayNetworkSelectionUI and imbues it with the essence of 1, which in the language of the registry, is akin to the ancient affirmation of "Yes." By setting DontDisplayNetworkSelectionUI to 1, you're instructing the Windows lockscreen to refrain from presenting the usual tapestry of network choices to wayfarers seeking entry (the Network Selection UI that typically appears when connecting to new networks). Instead, they must proceed based on knowledge previously imparted (existing network profiles) or through manual connection by ethernet. The above registry command addition prevents local windows wireless exploitation: the Airstrike attack https://shenaniganslabs.io/2021/04/13/Airstrike.html
:: -------------------------------------------------------------------
powershell.exe Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force
:: This spell, when cast, seeks out the LanmanServer in the labyrinthine registry under HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters. With a flick of your wand, you're looking to conjure a new decree named DisableCompression, setting its essence to 1 (the ancient digit of affirmation). The -Force at the end of your incantation ensures that your will is imposed upon the registry without hesitation, even if it means overriding the guards' protests or breaking ancient seals. What you're essentially doing is instructing the LanmanServer not to compress the files and data it serves to the denizens of your network. Compression, while a clever trick to make large tomes and scrolls occupy less space on the mystical carriages that transport them across the realm (your network), can sometimes be ensorcelled by malevolent forces to serve as a conduit for dark magic (exploits and vulnerabilities like CVE-2020-0796).
:: https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200005
:: -------------------------------------------------------------------
::###############################################################################################################
::
::      Windows Defender Device Guard Policies and Attack Surface Reduction Rules
:: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
:: -------------------------------------------------------------------
setx /M MP_FORCE_USE_SANDBOX 1
:: By invoking setx /M MP_FORCE_USE_SANDBOX 1, you're inscribing a permanent rune (environment variable) across the land (system-wide, thanks to /M) named MP_FORCE_USE_SANDBOX. You're imbuing this rune with the power of 1, which in the ancient digital scriptures signifies an unwavering 'Yes'. The essence of this spell, MP_FORCE_USE_SANDBOX, suggests it's meant to compel a certain guardian or sentinel (possibly related to Microsoft Defender or a similar security entity) to always use a sandbox for scrutinizing potentially malevolent spells (malicious software). A sandbox, in the lore of cybersecurity, is a secluded glade where unknown spells and artifacts can reveal their true nature without risking the greater realm.
:: -------------------------------------------------------------------
"%ProgramFiles%"\"Windows Defender"\MpCmdRun.exe -SignatureUpdate
:: By invoking this spell, you're navigating through the sacred halls of %ProgramFiles%, into the chambers of Windows Defender, to seek an audience with the sage MpCmdRun.exe. This wise entity is known for its ability to perform a variety of tasks, but with your specific directive -SignatureUpdate, you're asking it to refresh its knowledge of all known beasts and banshees (update its security intelligence signatures).
:: -------------------------------------------------------------------
:: Enable Defender signatures for Potentially Unwanted Applications (PUA)
powershell.exe Set-MpPreference -PUAProtection enable
:: By invoking the above preference of potentially unwanted apps to enable, you're consulting with the grand wizard of your kingdom, Windows Defender, and instructing it to sharpen its gaze specifically towards PUAs. The -PUAProtection enable part of the spell is particularly crucial; it’s like flipping on a magical lantern that reveals the shadows, making the invisible, unwanted critters visible and vulnerable. In non-moon speak, enabling PUA protection configures Windows Defender to detect and deal with applications that aren't necessarily malicious in the traditional sense but are often unwanted within the realm due to their behaviors or associations. These could be adware, toolbars, or other software that might slow down your feasts, spy on your court, or clutter your castle with unnecessary baubles.
:: -------------------------------------------------------------------
reg add "HKCU\SOFTWARE\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
:: By casting this incantation, you're enabling Defender for periodic scanning, navigating through the mystical forest of HKCU\SOFTWARE\Microsoft\Windows Defender. With the wave of your wand, you're looking to plant a new tree named PassiveMode, imbuing it with the essence of 2 through the alchemy of REG_DWORD. This act of magic, particularly the choice of 2 as the essence, is a curious one. Typically, setting PassiveMode involves a binary choice: 0 (disabled, letting Windows Defender actively protect your realm) or 1 (enabled, where it steps back, allowing other champions to lead the charge against digital dragons and goblins). The choice of 2 is like whispering an unknown spell, uncertain of the spirits' response, for it's a value not commonly recognized in the ancient tomes of Windows Defender. The /f flag at the end of your incantation ensures that your will is forced without question, overriding any previous enchantments or objections that might arise.
:: -------------------------------------------------------------------
powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $false"
::By invoking Set-MpPreference -DisableRealtimeMonitoring $false, you're calling upon the powers of PowerShell to communicate with Windows Defender. The -DisableRealtimeMonitoring part of the spell is particularly intriguing; it's akin to instructing the castle guards on whether they should be on high alert or stand down. With $false, you're affirming that the guards should indeed remain vigilant, keeping their eyes peeled and swords at the ready to fend off any digital marauders attempting to breach your fortress walls (in non-mystical terms, keeping real-time monitoring active to detect and stop malware as it arrives). This command is quite the strategic move, ensuring that your defenses are up and active, rather than leaving your gates unguarded. It's essential in these times, when digital sorcerers and shadowy figures lurk around every corner, waiting for an opportune moment to strike.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 0 /f
:: This incantation directs your command to delve into the depths of HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection, a crucial vault within the registry where the laws governing your realm's guardians (Windows Defender) are inscribed. By invoking DisableRealtimeMonitoring, you're addressing a specific decree that dictates whether the sentinels should constantly patrol the land (real-time monitoring). The essence you're choosing to imbue this decree with is 0 through the alchemy of REG_DWORD, which in the ancient binary tongue of the registry, signifies "False". What this means, my friend, is that you're reinforcing the command for the guardians to keep their eyes wide open, to never cease their vigilance against the dark spells and curses (malware and other threats) that might seek to invade your kingdom. The /f flag at the end of your spell ensures that your will is enacted without any need for confirmation, cutting through any bureaucratic red tape like a sword through shadow.
:: -------------------------------------------------------------------
reg add "HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 8 /f
::This incantation aims to etch a decree named DriverLoadPolicy within the mystical scrolls located at HKCU\SYSTEM\CurrentControlSet\Policies\EarlyLaunch, setting its essence to 1 with the alchemy of REG_DWORD. The choice of 1 for DriverLoadPolicy typically signifies a policy to only allow Early Launch AntiMalware drivers signed by Microsoft, ensuring that only the most trusted of spells (drivers) are invoked during the earliest moments of the realm's awakening (system startup). It's akin to instructing the gatekeepers to open the gates only for those bearing the royal seal, adding an extra layer of scrutiny to the guards' protocol. 3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'.
:: -------------------------------------------------------------------
powershell.exe Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
::The rule identified by D1E49AAC-8F56-4280-B9BA-993A6D77406C is known in the scrolls of the wise to target a particular type of threat. Depending on its nature, it could be a defense against scripts that malware might use, a blockade against obfuscated or potentially harmful scripts, or any number of specific protections designed to keep the kingdom's digital infrastructure safe from harm.
:: -------------------------------------------------------------------
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
:: The sigil you've invoked, D4F940AB-401B-4EFC-AADC-AD5F3C50688A, is a powerful one, likely designed to block Office applications from creating child processes, a specific form of dark sorcery known to plague the digital realms. It could be a ward against email threats that carry malevolent enchantments or a shield that prevents the execution of untrusted and suspicious spells.
:: -------------------------------------------------------------------
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions enable
:: The sigil 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 is a powerful one, tied to a particular ASR rule designed to safeguard your realm against specific threats like blocking Office applications from injecting code into other processes.
:: -------------------------------------------------------------------
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions enable
:: The rule identified by 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B is crafted to thwart a specific type of attack or exploit, blocking Win32 API calls from Office macros.
:: -------------------------------------------------------------------
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions enable
:: The rule marked by 3B576869-A4EC-4529-8536-B80A7769E899 is designed to counter a particular form of digital malevolence. The exact nature of this rule is to block Office applications from creating executable content.
:: -------------------------------------------------------------------
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
:: The rule identified by 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC is tailored to mitigate a specific threat, blocking the execution of potentially obfuscated scripts.
:: -------------------------------------------------------------------
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
::The rule linked with BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 is crafted to block executable content from email client and webmail. 
:: -------------------------------------------------------------------
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
::The rule associated with D3E037E1-3EB8-44C8-A917-57927947596D is crafted to mitigate a particular threat vector, blocking JavaScript or VBScript from launching downloaded executable content.
:: -------------------------------------------------------------------
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
:: The rule linked to 01443614-cd74-433a-b99e-2ecdc07bfc25 is crafted to block executable files from running unless they meet a prevalence, age, or trusted list criteria.
:: -------------------------------------------------------------------
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
:: The rule linked to C1DB55AB-C21A-4637-BB3F-A12568109D35 is crafted to use advanced protection against ransomware.
:: -------------------------------------------------------------------
:: Block credential stealing from the Windows local security authority subsystem (lsass.exe)
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
::The ASR rule identified by 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 is engineered to block credential stealing from the Windows local security authority subsystem (lsass.exe).
:: -------------------------------------------------------------------
:: Block untrusted and unsigned processes that run from USB
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
::The ASR rule tied to B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 is crafted to block untrusted and unsigned processes that run from USB. If you have a file that you know is for sure safe, you can right click on the file and go to properties then click the unblock checkbox option.
:: -------------------------------------------------------------------
powershell.exe Set-MpPreference -MAPSReporting Advanced
:: Cranking up MAPSReporting to "Advanced" with your PowerShell wand is like sending your digital scouts far and wide by enabling cloud functionality with Windows Defender, gathering more intel on every shadow and whisper. This move beefs up your fortress's defenses, allowing your guardians to learn from the battles of others and sharpen their blades against new threats faster.
:: -------------------------------------------------------------------
powershell.exe Set-MpPreference -SubmitSamplesConsent SendAllSamples
::Wielding this PowerShell command is akin to opening the gates of your fortress and allowing your messengers to carry all discovered mysterious tomes and artifacts (samples) straight to the grand council (Microsoft) for examination
:: -------------------------------------------------------------------
powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError
:: This PowerShell command is like casting a multi-faceted 7 step complex spell to enhance the armor and agility of your kingdom's defenders (system processes), making them more resilient against cunning attacks from dark sorcerers (exploit techniques). 
:: 1. DEP (Data Execution Prevention): This is akin to training your guards to distinguish between a real sword and a decoy, preventing attackers from tricking the system into executing malicious code disguised as data.
:: 2. EmulateAtlThunks: This can be thought of as teaching your sentinels ancient combat techniques to better defend against specific, outdated forms of attack, enhancing compatibility while maintaining security.
:: 3. BottomUp: By randomizing the layout of your city (memory space), you make it harder for invaders to predict and find their way around, thwarting their plans.
:: 4. HighEntropy: This is like adding more complexity to your city's layout with additional secret passages and hidden rooms, making it even more difficult for attackers to navigate.
:: 5. SEHOP (Structured Exception Handler Overwrite Protection): It's akin to safeguarding the royal messengers' routes, ensuring that no imposter can intercept or manipulate their messages to cause chaos.
:: 6. SEHOPTelemetry: This sends signals back to the royal council every time an imposter is caught, helping to improve the overall defense strategies.
:: 7. TerminateOnError: This ensures that if a guard spots something amiss, they immediately shut the gates, stopping any process that behaves unexpectedly to prevent potential damage.
:: -------------------------------------------------------------------
powershell.exe Set-MpPreference -EnableNetworkProtection Enabled 
:: This is the heart of the spell, where you're activating the network protection. It's akin to deploying sentries to every bridge and gate, equipped with the foresight to recognize and halt invaders (malicious web traffic) before they can even set foot on your soil. By enabling Network Protection, you're essentially fortifying the borders of your digital domain against phishing attacks, exploits, and other malicious content that lurks on the web. It's a proactive measure, stopping threats at the network level and preventing them from reaching your inner sanctum (endpoints like PCs and servers).
:: -------------------------------------------------------------------
::###############################################################################################################
::
::      MICROSOFT OFFICE HARDENING
::
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Security" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\PowerPoint\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\PowerPoint\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Word\Options\vpref\fNoCalclinksOnopen_90_1" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\12.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Options\DontUpdateLinks" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Security" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\PowerPoint\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\PowerPoint\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\14.0\Word\Security" /v AllowDDE /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Options\DontUpdateLinks" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Security" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\PowerPoint\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\PowerPoint\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Security" /v AllowDDE /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Options\DontUpdateLinks" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security" /v WorkbookLinkWarnings /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security" /v PackagerPrompt /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 4 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security" /v AllowDDE /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\Security" /v DisableAllActiveX /t REG_DWORD /d 1 /f
:: These registry tweaks tighten the security across Office apps like Excel, PowerPoint, and Word, across versions from 2007 to 2016 and possibly Office 365. They mainly: Block sneaky insertions via OLE Package Manager, silence macro warnings, only letting through those with a digital handshake, dial down alerts for links in workbooks, stop Excel from automatically chasing down external links, close the door on DDE in Word, keeping out a tricky way attackers chat with your docs, and put a stop to all ActiveX antics.
::
::###############################################################################################################
::
::      GENERAL OS HARDENING
::
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 0 /f
:: This adjustment is like closing the castle gates to unknown travelers, allowing only those within your walls to supply scrolls (printer drivers), thus safeguarding your realm against potential threats carried from distant lands (no print drivers supplied over the network. Setting the AddPrinterDrivers value to 0 in the registry primarily affects the ability to install printer drivers from network locations. This setting won't directly impact the "plug and play" capability for printers connected locally to your computer, such as through a USB port. For local printers connected directly to your computer, Windows typically uses already installed drivers or drivers that come with the operating system to facilitate "plug and play" functionality. If a specific driver is needed and not already available on your system, you might need to install it manually.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateDASD /t REG_DWORD /d 0 /f
:: By executing this command, you're essentially tightening security by restricting disk space allocation to users with administrative rights during the logon process. This can help prevent unauthorized users from performing certain actions that could affect the system's integrity or security. However, it's important to understand the implications of this change in environments where users might need to allocate disk space during logon for legitimate reasons. Users might need to allocate disk space during logon in specialized environments like virtual desktops, temporary workstations, or when using certain heavy-duty applications. This is also common in scenarios where user profiles are dynamically configured at each logon, or where specific logon scripts and policies necessitate temporary storage for updates, settings, or user data. These requirements are typically more prevalent in managed IT infrastructures rather than everyday user settings.
:: Forces Installer to NOT use elevated privileges during installs by default, which prevents escalation of privileges vulnerabilities and attacks.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
:: You're essentially telling your guards (the Windows Installer) to not automatically give the royal treatment (elevated privileges) to every traveler (installation package) that approaches. Instead, they'll need to prove they're worthy of entering the keep (get explicit permission), making sure only those with a genuine royal decree (administrator approval) can make significant changes within your walls. It's a wise move to keep out unwanted mischief-makers, although it means the heralds (administrators) might be called upon more frequently to lower the bridge.
:: -------------------------------------------------------------------
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f
:: By setting UseLogonCredential to 0, you're instructing the WDigest security protocol in your realm to not store logon credentials in memory. In the old days, WDigest could leave a trace of the password in memory, potentially allowing sneaky spies (malicious actors) to uncover it. Disabling this ensures that even if intruders sneak past the gates, they won't find any valuable secrets lying around, bolstering the security of your domain. It's a strategic move to keep your treasures (credentials) locked in the vault, away from prying eyes.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
:: This spell upgrades the armor of your Kerberos knights, making sure they only parley using the strongest of magical ciphers. The 2147483640 enchantment ensures they're not caught whispering secrets in weak tongues.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
::  Silencing the Multicast Echoes: By turning off the multicast ability, you're telling your heralds to stop shouting across the lands, making them tread more quietly and drawing less attention from nosey passersby.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
:: Disabling smart name guessing tells your scouts to stick to the paths they know, without taking risky shortcuts through the dark woods of DNS, keeping their journeys predictable and safe.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
:: Single-file March: Stopping parallel DNS queries is like telling your messengers to march one behind the other instead of side by side, avoiding the confusion at the crossroads and making sure no one gets lost or ambushed.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f
:: By enacting this command, you're ensuring your realm's network messengers keep to themselves, not getting involved in the broader multicast gatherings that might be unnecessary or pose a security risk. It's a move towards simplicity and caution, ensuring your communications remain private and undisturbed by external chatter.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
:: By invoking this command, you're effectively sealing off backdoors and hidden passages that could be exploited to reroute or snoop on your messengers, fortifying the integrity and security of your kingdom's communications.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
:: With this command, you're bolstering your kingdom's defenses by ensuring that the flow of information remains steady and unswayed by potentially misleading or harmful detours, keeping the integrity of your communications network intact.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
:: By enacting this command, you're ensuring the secure and unaltered passage of messages across your IPv6 territories, shielding your communications from potential subterfuge and maintaining the sanctity of your realm's networking routes. This edict instructs your IPv6 messengers to disregard any external suggestions to alter their predestined routes, a practice that could expose them to ambushes or misdirection by ne'er-do-wells. By imbuing this decree with the essence of 2, you're not only forbidding these external influences but also setting up a watchtower to report any attempts at such trickery, keeping you informed of potential deceit.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
:: Executing this command fortifies your realm's security by ensuring that communications and exchanges no longer traverse the outdated and vulnerable SMB1 pathway, favoring more secure, modern routes instead. It's a wise move to protect the integrity and safety of your kingdom's exchanges and dialogues. This particular edict targets the SMB1 protocol, an old set of rules for sharing scrolls and artifacts (files and printers) across your domain. By setting this to 0, you're ordering the closure of this ancient pathway. Imbuing the decree with the essence of 0 signifies that the SMB1 protocol is to be disabled, preventing its use due to its vulnerability to siege engines and dark spells (exploits and attacks).
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
:: Enacting this command strengthens your realm's security posture by ensuring that all interactions with your server services are authenticated, effectively reducing the risk of unauthorized access or reconnaissance by nefarious entities. By setting this decree, you're specifically targeting how the realm deals with "null sessions" – essentially, connections that don't provide any credentials.Setting its essence to 1 acts as a firm "Yes" to restricting these anonymous access attempts, ensuring that every entity that wishes to communicate or transact within your domain must present proper credentials.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
:: By enacting this command, you're bolstering the realm's defenses, ensuring that any attempt to invoke significant change or access sensitive quarters is met with scrutiny, maintaining the sanctity and security of your domain. This specific decree concerns the User Account Control (UAC), a vigilant guardian that questions the intent of those seeking to perform acts that could alter the kingdom's landscape. By setting its essence to 1, you affirm the guardian's vigilance, ensuring that every action that could impact the realm's stability is scrutinized, and only proceeds with the rightful consent.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
:: Implementing this command fortifies your domain's security, leveraging the latest magical defenses to protect against sophisticated threats, ensuring the safety and integrity of your realm's operations. This particular decree activates a powerful form of magic known as "virtualization-based security" (VBS). It creates secure, isolated compartments within your kingdom, safeguarding your treasures (sensitive data and system processes) against marauders. By setting its essence to 1, you're affirming the activation of this protective magic, ensuring that your realm's most sensitive and critical operations are enveloped in an extra layer of security.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 1 /f
:: This command is like instructing the royal guards to usher administrators into a secure, dimly lit chamber whenever a significant decision needs their seal of approval. This particular decree mandates how the realm's advisors (administrators) are summoned for counsel. By setting its essence to 1, you're ensuring that whenever the realm's wisdom is sought (admin actions), it's done in a secluded, secure space away from prying eyes and ears, signified by the chamber's dimming lights.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f
:: With this command, you're enhancing the awareness of your subjects about the origins of the digital goods they encounter, allowing for a balance between security and usability. It's a wise rule that fosters both caution and convenience in the realm. This edict determines how the origin of goods is recorded. By setting its essence to 2, you're decreeing that goods from outside the kingdom will be marked with their origin, but in a way that doesn't prevent them from being used or sold within the marketplace. It ensures there's awareness of where things come from without overly restricting their use.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f
:: By enacting this command, you're maintaining strong defenses against hidden threats that lurk in the shadows, ensuring the safety and integrity of your realm's artifacts and lore. It's a wise move to keep the protective enchantments robust and ever-vigilant. This particular decree is about Data Execution Prevention (DEP), a powerful ward that prevents certain types of spells (code) from taking harmful actions in your realm's memory. Setting its essence to 0 reinforces the protection, ensuring that the DEP safeguards remain strong and active, guarding against malicious spells that seek to animate the inanimate for nefarious purposes.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f
:: By issuing this command, you're ensuring that your kingdom remains vigilant against internal decay, swiftly addressing any signs of corruption to prevent further damage and maintain the stability and security of your realm's operations. This decree focuses on the heap (a crucial part of your kingdom's memory architecture), specifically how it responds to corruption or damage. Setting its essence to 0 commands that any corruption detected within the heap should lead to an immediate halt of the affected structure (process termination), preventing the spread of corruption and maintaining the overall integrity of your domain.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
:: By applying this command, you're enhancing the security of your domain's wireless communications, ensuring that connections are made judiciously and reducing the risk of inadvertently connecting to potentially compromised or unsafe networks. It's a strategic move to maintain the sanctity and security of your realm's communications. This particular decree dictates whether devices in your realm can automatically seek out and connect to known networks without explicit permission each time. Setting its essence to 0 enforces a policy of caution, disallowing your devices from automatically connecting to networks, even those previously recognized as friendly. This ensures that each connection is made deliberately and with mindfulness to security. It specifically impacts how Original Equipment Manufacturer (OEM)-specific connections or profiles are handled, not your home WiFi.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f
:: With this command, you're enhancing the security of your realm's communications, ensuring that connections are made judiciously and reducing the risk of inadvertently connecting to potentially compromised or unsafe networks. It's a strategic move to maintain the sanctity and security of your realm's communications. By proclaiming this decree, you're instructing your realm's carriers to refrain from engaging with every waystation or tavern (network) they encounter, especially those unfamiliar or less trusted, unless absolutely necessary. Setting its essence to 1 solidifies this policy, emphasizing prudence and restraint in forming new connections, thereby safeguarding your domain's secrets.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
:: By invoking this command, you're enhancing the security and stability of your realm's network identity, ensuring that its names and titles cannot be easily usurped or contested by external forces, thereby maintaining the integrity and order of your digital kingdom. This decree commands that your heralds (NetBIOS names) shall not be forsaken or released simply because an outsider demands it, safeguarding your realm's claims and titles against deceptive practices. By setting its essence to 1, you're affirming this protective measure, ensuring that the names and titles within your realm are held with the gravity and permanence they deserve.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictReceivingNTLMTraffic /t REG_DWORD /d 2 /f
:: By casting this command, you're significantly enhancing the security of your domain's communications, ensuring that only the most secure and scrutinized messages are allowed passage, thereby safeguarding the integrity and confidentiality of your realm's affairs. This decree specifically targets NTLM traffic, an older method of sending messages within and beyond the kingdom's walls. By invoking this, you aim to restrict these ancient pathways, known for their vulnerability to eavesdroppers and tricksters. Setting its essence to 2 elevates the security protocols, effectively closing the gates to incoming NTLM messages unless they meet stringent criteria, thereby fortifying your kingdom against potential subterfuge. THIS COULD IMPACT RDP CONNECTIONS to desktops from other domain users and machines. Only keep it enabled in environments where you don't use RDP to internal user machines or you don't allow users to share folders on their machines.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 2 /f
:: With this command, you're bolstering your domain's security posture by ensuring that all outbound communications are subject to strict scrutiny, thereby protecting your kingdom's secrets and maintaining the integrity of your diplomatic communications. This decree mandates the conditions under which your kingdom's messengers (NTLM traffic) can venture forth, aiming to restrict the use of older, less secure protocols when communicating with foreign lands. By setting its essence to 2, you're enforcing a policy that essentially bars the sending of NTLM traffic, except under certain secure conditions, thereby preventing potential eavesdroppers from intercepting and deciphering your messages. THIS BREAKS RDP (outgoing to other domain machines) & SHARES.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f
:: By invoking this command, you're ensuring that any use of NTLM within your kingdom's servers is subject to stringent security protocols, effectively reinforcing your defenses against would-be infiltrators and ensuring the safety and integrity of your realm's communications and transactions. This decree sets forth the minimum security requirements for NTLM, an ancient but still-used method of verifying the identities of those who wish to enter or communicate with your kingdom. The essence of 537395200 is a potent combination of protective spells, requiring that all NTLM communications adhere to strong security measures, including message confidentiality, integrity, and authentication.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f
:: With this decree, you're fortifying the security protocols for your kingdom's clients, guaranteeing that any use of the NTLM protocol for communication is subject to rigorous security requirements, thus bolstering your defenses and ensuring the safety and integrity of your realm's communications. This command mandates the minimum security standards that must be met by your realm's emissaries (client systems) when they employ the NTLM protocol, an old but still utilized method for secure identification and message exchange. By setting its essence to 537395200, you're invoking powerful protective magics, requiring that all NTLM communications by clients maintain high standards of message confidentiality, integrity, and proper authentication.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f
:: By enacting this command, you're ensuring a higher standard of security across your realm, closing off a potential vulnerability and thereby reinforcing the overall safety and integrity of your kingdom's interactions and transactions. This specific decree addresses the fallback to null sessions, a state where individuals could previously gain limited access without full authentication under certain conditions. Setting its essence to 0 effectively enforces a ban on this practice, ensuring that every individual must fully authenticate themselves to gain any level of access, thereby eliminating a weaker link in your kingdom's defenses.
:: -------------------------------------------------------------------
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f
:: By invoking this command, you're significantly enhancing the security of your realm's communications, ensuring that all interactions meet a high standard of authentication and encryption, thus safeguarding the integrity and confidentiality of your domain's affairs. This decree sets the level of compatibility for the Lan Manager (LM), which pertains to the authentication methods your envoys are permitted to use when verifying their identities and securing their messages. Imbuing this decree with the essence of 5 commands that only the most advanced and secure authentication protocols be used, eschewing older, less secure methods. This level ensures that NTLMv2 responses are used and that LM and NTLM responses, known for their vulnerabilities, are refused, fortifying your kingdom against potential subterfuge. THIS SETTING COULD IMPACT SHARE ACCESS.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
:: By casting this command, you're enhancing the security of your realm, ensuring that the identities and roles within your domain remain confidential, safeguarded from the eyes of those who wander your lands without a name or purpose. This specific decree targets the Security Account Manager (SAM), which holds the detailed scrolls of all subjects' identities and their access rights within your realm. Setting this policy restricts anonymous inquiries, preventing unknown entities from gleaning information about the realm's inhabitants. By setting its essence to 1, you command that the SAM only entertains queries from those who can prove their identity, effectively barring anonymous entities from accessing sensitive information.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
:: By invoking this command, you're fortifying the privacy and integrity of your kingdom's resources, ensuring that only those with clear intent and identity can interact with and learn from the collective wisdom and assets of your domain. This decree specifically targets anonymous visitors, restricting their ability to obtain information from the kingdom's ledger (the system's resources and information). Setting its essence to 1 enforces a level of restriction that curtails the capabilities of those without a recognized identity to query or interact with the system's resources, ensuring they cannot access or glean information without proper authorization.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
:: By casting this command, you're making a clear distinction in your realm's policies, ensuring that communal rights and privileges are reserved for those whose identities are known and verified, further safeguarding the collective resources and wisdom of your domain. This specific command clarifies who is considered part of "everyone" within your domain, explicitly excluding those anonymous wanderers from the collective privileges and access rights. Imprinting the essence of 0 on this decree, you're ensuring that anonymous entities are not counted among "everyone," thereby tightening the security and integrity of who can access your kingdom's resources and secrets.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
:: By casting this command, you're ensuring that only those within your inner circle, carrying the badge of authority, can access or query the SAM database from afar, thereby protecting your realm's sensitive information from prying eyes and unauthorized access. This command sets a new rule for the Security Account Manager (SAM), which acts like the gatekeeper to your kingdom's identity records, determining who can query this information remotely. This intricate incantation specifies who can access the SAM database remotely. It's crafted in the language of security descriptors, with this particular spell granting read control (RC) permissions exclusively to the built-in administrators group (BA), effectively locking out anyone who doesn't possess administrative privileges.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f
:: By enacting this command, you're enhancing the traceability and accountability of actions within your kingdom, ensuring that every move can be attributed to its maker, thus bolstering the integrity and security of your realm's operations. This command is like assigning a unique seal or emblem to each of your kingdom's messengers and scouts, ensuring that their messages can be traced back to their origin, adding an extra layer of accountability and security. This command instructs that each communication or transaction within your kingdom must carry the unique identifier of its origin (the machine ID), akin to a wax seal on a scroll. Setting its essence to 1 activates this identification measure, ensuring that every action can be traced back to its source, much like knowing which scribe penned which document.
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
:: This command is like setting a decree that mandates every gatekeeper and guardian within your realm to require a passphrase from anyone wishing to enter, thereby forbidding the ancient practice of allowing entry through silence or a mere nod. This specific command reinforces the notion that every entity, be it a humble scribe or a high council member, must present a passphrase (password) to gain access to the kingdom's resources, effectively eliminating the loophole where one could gain access with no passphrase at all. By setting its essence to 1, you're ensuring that this practice is strictly enforced, closing off any paths that once allowed unfettered access based merely on the absence of a passphrase.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v WpadOverride /t REG_DWORD /d 1 /f
:: This command is akin to placing a wise elder at every crossroad within your kingdom, tasked with advising travelers to rely on their maps and knowledge rather than the whimsical and often misleading whispers of the wind, known as Web Proxy Auto-Discovery (WPAD). This command establishes a new guideline, advising against the automatic use of WPAD, a method that can sometimes lead travelers astray by directing them through potentially hazardous routes. Imprinting the essence of 1 on this decree, you're instructing your subjects to be cautious, encouraging them to override the use of WPAD and instead rely on predetermined, trusted paths for their journeys. By enacting this command, you're enhancing the safety and reliability of your kingdom's communications, ensuring that your subjects and their messages traverse only the safest and most secure routes, guarded against the misleading and sometimes perilous suggestions that WPAD might offer.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
:: This command is like setting a decree in your kingdom that ensures the local nobility (administrators) on remote estates (networked computers) do not wield their full powers when dealing with affairs from afar, aligning with the principle that one's influence is most potent within their own castle walls. This particular command governs how the realm recognizes the authority of local administrators when they're managing resources or making decisions from a remote vantage point. Setting its essence to 0 reinforces the standard security measure known as User Account Control (UAC) remote restrictions. It ensures that even high-ranking officials (administrators) are subject to a check of their credentials and permissions when they seek to influence the domain from beyond their immediate jurisdiction. This affects Windows Remoting (WinRM) deployments.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
:: This command is like setting up a checkpoint within your kingdom, ensuring that even the highest-ranking officials (administrators) must confirm their identity and intentions before wielding their power. This decree mandates that actions requiring elevated privileges must be consciously invoked by administrators, ensuring that such powers aren't applied unintentionally or without due consideration. Setting its essence to 1 activates this checkpoint, requiring a clear, deliberate act to confirm the use of administrative powers, akin to a knight donning their armor with purpose before a battle. By casting this command, you're enhancing the safeguards within your realm, ensuring that significant actions are taken with mindfulness and explicit intent, thus preserving the integrity and security of your domain.
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f
:: This command is like establishing a rule within your kingdom that dictates how envoys from distant lands (remote clients) are allowed to interact within your realm, specifically through the ancient and powerful communication channels known as RPC (Remote Procedure Calls). This command sets forth a decree that limits the access of these distant envoys, ensuring they can only engage with your realm under more controlled and restricted conditions, thus preventing them from wielding undue influence or accessing sensitive areas unattended. By setting its essence to 1, you're enacting a level of restriction, akin to requiring distant visitors to be accompanied by one of your own trusted guides when they wish to converse or transact within your kingdom, ensuring their actions are monitored and contained. 
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /t REG_DWORD /d 0 /f
:: This command is like issuing a royal directive in your digital realm that conceals the controls for sharing the kingdom's vital pathways (network connections) from the public eye, ensuring that only those with the right knowledge and authority can access and manage these communal resources. This decree specifically targets the visibility of the user interface for network sharing settings, making such options unseen by the general populace to prevent unauthorized manipulation. By setting its essence to 0, you're enacting a veil of invisibility over these controls, ensuring that the mechanisms for sharing the kingdom's network connections remain a closely guarded secret.
:: -------------------------------------------------------------------
:: Enable SMB/LDAP Signing
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f
:: 1- Negotiated; 2-Required
:: -------------------------------------------------------------------
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 2 /f
:: -------------------------------------------------------------------
reg add "HKLM\System\CurrentControlSet\Services\ldap" /v "LDAPClientIntegrity " /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
:: Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
:: Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
:: Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
:: Enable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f
:: -------------------------------------------------------------------
:: Enforce NTLMv2 and LM authentication
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
:: -------------------------------------------------------------------
:: Prevent unencrypted passwords being sent to third-party SMB servers
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
:: -------------------------------------------------------------------
:: Prevent guest logons to SMB servers
:: This is commented out by default as it could impact access to consumer-grade file shares but it's a recommended setting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
:: -------------------------------------------------------------------
:: Prevent (remote) DLL Hijacking
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v CWDIllegalInDllSearch /t REG_DWORD /d 0x2 /f
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
:: The value data can be 0x1, 0x2 or 0xFFFFFFFF. If the value name CWDIllegalInDllSearch does not exist or the value data is 0 then the machine will still be vulnerable to attack.
:: Please be aware that the value 0xFFFFFFFF could break certain applications (also blocks dll loading from USB).
:: Blocks a DLL Load from the current working directory if the current working directory is set to a WebDAV folder  (set it to 0x1)
:: Blocks a DLL Load from the current working directory if the current working directory is set to a remote folder (such as a WebDAV or UNC location) (set it to 0x2)

::
:: Disable (c|w)script.exe to prevent the system from running VBS scripts
:: ---------------------
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v ActiveDebugging /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v DisplayLogo /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v SilentTerminate /t REG_SZ /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v UseWINSAFER /t REG_SZ /d 1 /f
::
:: Disable IPv6
:: https://support.microsoft.com/en-us/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users
:: ---------------------
reg add "HKLM\SYSTEM\CurrentControlSet\services\tcpip6\parameters" /v DisabledComponents /t REG_DWORD /d 0xFF /f
:: Windows Update Settings
:: Prevent Delivery Optimization from downloading Updates from other computers across the internet
:: 1 will restrict to LAN only. 0 will disable the feature entirely
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f
::reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f
:: Set screen saver inactivity timeout to 15 minutes
::reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f
:: Enable password prompt on sleep resume while plugged in and on battery
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f
::
:: Windows Remote Access Settings
:: Disable solicited remote assistance
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
:: Require encrypted RPC connections to Remote Desktop
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
:: Prevent sharing of local drives via Remote Desktop Session Hosts
::reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
:: 
:: Removal Media Settings
:: Disable autorun/autoplay on all drives
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
::
:: Stop WinRM Service
net stop WinRM
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
:: Disable WinRM Client Digiest authentication
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowDigest /t REG_DWORD /d 0 /f
net start WinRM
:: Disabling RPC usage from a remote asset interacting with scheduled tasks
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f
:: Disabling RPC usage from a remote asset interacting with services
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f
::
:: Stop NetBIOS over TCP/IP
wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
:: Disable NTLMv1
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f
:: Disable Powershellv2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
::
::#######################################################################
:: Harden lsass to help protect against credential dumping (Mimikatz)
:: Configures lsass.exe as a protected process and disables wdigest
:: Enables delegation of non-exported credentials which enables support for Restricted Admin Mode or Remote Credential Guard
:: https://technet.microsoft.com/en-us/library/dn408187(v=ws.11).aspx
:: https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5
:: ---------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f
::
::#######################################################################
:: Disable the ClickOnce trust promp
:: this only partially mitigates the risk of malicious ClickOnce Appps - the ability to run the manifest is disabled, but hash retrieval is still possible
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v MyComputer /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v LocalIntranet /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v Internet /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v TrustedSites /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v UntrustedSites /t REG_SZ /d "Disabled" /f
::
::#######################################################################
:: Enable Windows Firewall and configure some advanced options
:: Block Win32/64 binaries (LOLBins) from making net connections when they shouldn't
:: ---------------------
netsh Advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh Advfirewall set allprofiles state on
::
:: Disable TCP timestamps
netsh int tcp set global timestamps=disabled
::
:: Enable Firewall Logging
:: ---------------------
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
::
:: Block all inbound connections on Public profile - enable this only when you are sure you have physical access. 
:: To restore the consequences of the next command, run the one after it. This will disable RDP and Share and all other inbound connections to this computer. 
:: ---------------------
:: !!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!
:: The following command enables RDP before you block all other ports - use the same logic for any other ports you might need open before you block inbound connections.
:: netsh advfirewall firewall add rule name="Open Remote Desktop" protocol=TCP dir=in localport=3389 action=allow
:: netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound
:: The following command ignores the RDP or any other rule above and blocks ALL inbound connections. Use this when you connect to the remote machine
:: for troubleshooting using an agent or don't connect remotely at all, as you will not be able to use RDP or other means of remote administration after this. 
:: netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
:: 
:: the two commands work extremely well and it is recommended that you edit this script according to your needs and the needs of specific users and departments in your company. 
::
::Disable AutoRun
:: ---------------------
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
::
::Show known file extensions and hidden files
:: ---------------------
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
::
::Disable 8.3 names (Mitigate Microsoft IIS tilde directory enumeration) and Last Access timestamp for files and folder (Performance)
:: ---------------------
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 0
::
:: Biometrics
:: Enable anti-spoofing for facial recognition
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
:: Disable other camera use while screen is locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
:: Prevent Windows app voice activation while locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
:: Prevent Windows app voice activation entirely (be mindful of those with accesibility needs)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f
::
:: Disable weak TLS/SSL ciphers and protocols
:: ---------------------
:: https://www.nartac.com/Products/IISCrypto
:: https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/operations/manage-ssl-protocols-in-ad-fs
:: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786418(v=ws.11)
:: https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
:: Encryption - Ciphers: AES only - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /v Enabled /t REG_DWORD /d 0 /f
:: Encryption - Hashes: All allowed - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" /v Enabled /t REG_DWORD /d 0xffffffff /f
:: Encryption - Key Exchanges: All allowed
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v ServerMinKeyBitLength /t REG_DWORD /d 0x00001000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" /v Enabled /t REG_DWORD /d 0xffffffff /f
:: Encryption - Protocols: TLS 1.0 and higher - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
:: Encryption - Cipher Suites (order) - All cipher included to avoid application problems
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v Functions /t REG_SZ /d "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256" /f
::
:: OCSP stapling - Enabling this registry key has a potential performance impact
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v EnableOcspStaplingForSni /t REG_DWORD /d 1 /f
::
:: Enabling Strong Authentication for .NET Framework 3.5
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
:: Enabling Strong Authentication for .NET Framework 4.0/4.5.x
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SystemDefaultTlsVersions /t REG_DWORD /d 1 /f
::
::
::##################################################################################################################
:: 
::      Additional Windows Defender For Business Recommendations
::
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA" /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_AllowNetBridge_NLA /t REG_DWORD /d 0 /f
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableDomainCreds /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" /v EnumerateAdministrators /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v AllowLocalIPsecPolicyMerge /t REG_DWORD /d 0 /f
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_StdDomainUserSetLocation /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowBasic /t REG_DWORD /d 0 /f
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 0 /f
:: -------------------------------------------------------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext" /v VersionCheckEnabled /t REG_DWORD /d 1 /f
:: -------------------------------------------------------------------
::
::###############################################################################################################
::
::      Microsoft Windows 11 Security Technical Implementation Guide (STIG)
:: 
::      This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DOD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Included below are several modification to improve security.
::
BCDEDIT /set {current} nx OptOut
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowBasic /t REG_DWORD /d 0 /f

:: -------------------------------------------------------------------

::#######################################################################
:: Microsoft Windows 11 Security Technical Implementation Guide
::     This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DOD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. https://www.stigviewer.com/stig/microsoft_windows_11/
::#######################################################################
::
::#######################################################################
:: Enable and Configure Internet Browser Settings
::#######################################################################
::
:: Enable SmartScreen for Edge
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
:: Enable Notifications in IE when a site attempts to install software
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
:: Disable Edge password manager to encourage use of proper password manager
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f
::
::
::#######################################################################
:: Windows Privacy Settings
::#######################################################################
::
:: Set Windows Analytics to limited enhanced if enhanced is enabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f
:: Set Windows Telemetry to security only
:: If you intend to use Enhanced for Windows Analytics then set this to "2" instead
:: Note my understanding is W10 Home edition will do a minimum of "Basic"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f
:: Disable location data
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v Location /t REG_SZ /d Deny /f
:: Prevent the Start Menu Search from providing internet results and using your location
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
:: Disable publishing of Win10 user activity 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f
:: Disable Win10 settings sync to cloud
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
:: Disable the advertising ID
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
::
:: Disable Windows GameDVR (Broadcasting and Recording)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
:: Disable Microsoft consumer experience which prevent notifications of suggested applications to install
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
:: Disable websites accessing local language list
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
:: Prevent toast notifications from appearing on lock screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f
::
::#######################################################################
:: Enable Advanced Windows Logging
::#######################################################################
::
:: Enlarge Windows Event Security Log Size
wevtutil sl Security /ms:1024000
wevtutil sl Application /ms:1024000
wevtutil sl System /ms:1024000
wevtutil sl "Windows Powershell" /ms:1024000
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000
:: Record command line data in process creation events eventid 4688
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
::
:: Enabled Advanced Settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
:: Enable PowerShell Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
::
:: Enable Windows Event Detailed Logging
:: This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
:: For more extensive Windows logging, I recommend https://www.malwarearchaeology.com/cheat-sheets
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
:: Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
:: Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
:: Uninstall common extra apps found on a lot of Windows installs
:: Obviously do a quick review to ensure it isn't removing any apps you or your user need to use.
:: https://docs.microsoft.com/en-us/windows/application-management/apps-in-windows-10
powershell.exe -command "Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Getstarted* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Messaging* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Microsoft3DViewer* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* -AllUsers | Remove-AppxPackage"
:: powershell.exe -command "Get-AppxPackage *Microsoft.MicrosoftNotes* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.MixedReality.Portal* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.OneNote* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.OneConnect* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Print3D* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Wallet* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WebMediaExtensions* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WebpImageExtension* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsAlarms* -AllUsers | Remove-AppxPackage"
:: powershell.exe -command "Get-AppxPackage *Microsoft.WindowsCamera* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *microsoft.windowscommunicationsapps* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedbackHub* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsMaps* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsSoundRecorder* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Xbox.TCUI* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGameOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxGamingOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxIdentityProvider* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.ZuneVideo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedback* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Windows.ContactSupport* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *PandoraMedia* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *AdobeSystemIncorporated. AdobePhotoshop* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Duolingo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.BingNews* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Office.Sway* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Services.Store.Engagement* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *ActiproSoftware* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *EclipseManager* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *SpotifyAB.SpotifyMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *king.com.* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.NET.Native.Framework.1.* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *netflix* | Remove-AppxPackage"
:: Removed Provisioned Apps
:: This will prevent these apps from being reinstalled on new user first logon
:: Obviously I manually chose this list. If you truly want to nuke all the provisioned apps, you can use the below commented command in PowerShell
:: Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.GetHelp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Getstarted'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftOfficeHub'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftSolitaireCollection'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MixedReality.Portal'} | Remove-AppxProvisionedPackage -Online"
:: powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsAlarms'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'microsoft.windowscommunicationsapps'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsFeedbackHub'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsMaps'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsSoundRecorder'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxApp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxTCUI'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGameOverlay'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGamingOverlay'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxIdentityProvider'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneMusic'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneVideo'} | Remove-AppxProvisionedPackage -Online"
::
:: Adobe Reader DC STIG
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" /f
reg add "HKLM\Software\Adobe\Acrobat Reader\DC\Installer" /v "DisableMaintenance" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bAcroSuppressUpsell" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bDisablePDFHandlerSwitching" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bDisableTrustedFolders" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bDisableTrustedSites" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bEnableFlash" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bProtectedMode" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "iFileAttachmentPerms" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "iProtectedView" /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" /v "bAdobeSendPluginToggle" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" /v "iURLPerms" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" /v "iUnknownURLPerms" /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bToggleAdobeDocumentServices" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bToggleAdobeSign" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bTogglePrefsSync" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bToggleWebConnectors" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bUpdater" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" /v "bDisableSharePointFeatures" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" /v "bDisableWebmail" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" /v "bShowWelcomeScreen" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" /v "DisableMaintenance" /t REG_DWORD /d 1 /f
::
:: Prevent Edge from running in background
:: On the new Chromium version of Microsoft Edge, extensions and other services can keep the browser running in the background even after it's closed. 
:: Although this may not be an issue for most desktop PCs, it could be a problem for laptops and low-end devices as these background processes can 
:: increase battery consumption and memory usage. The background process displays an icon in the system tray and can always be closed from there. 
:: If you run enable this policy the background mode will be disabled.
reg add "HKLM\Software\Policies\Microsoft\Edge" /f
reg add "HKLM\Software\Policies\Microsoft\Edge"  /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f
::
:: EDGE HARDENING ::
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SitePerProcess" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLVersionMin" /t REG_SZ /d "tls1.2^@" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NativeMessagingUserLevelHosts" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverride" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverrideForFiles" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLErrorOverrideAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenPuaEnabled" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AllowDeletingBrowserHistory" /t REG_DWORD /d "0x00000000" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist\1" /t REG_SZ /d "odfafepnkmbhccpbejgmiehpchacaeak" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist\1" /t REG_SZ /d "odfafepnkmbhccpbejgmiehpchacaeak" /f
reg add "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak" /v "update_url" /t REG_SZ /d "https://edge.microsoft.com/extensionwebstorebase/v1/crx" /f
::
::#######################################################################
:: Enable and Configure Google Chrome Internet Browser Settings
::#######################################################################
::
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d on /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 1 /f
::
:: #####################################################################
:: Chrome hardening settings
:: #####################################################################
reg add "HKLM\Software\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "RemoteAccessHostFirewallTraversal" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultPopupsSetting" /t REG_DWORD /d "33554432" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultGeolocationSetting" /t REG_DWORD /d "33554432" /f
:: reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderSearchURL" /t REG_SZ /d "https://www.google.com/#q={searchTerms}" /f
:: reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderEnabled" /t REG_DWORD /d "16777216" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "AllowOutdatedPlugins" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "CloudPrintProxyEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "ImportSavedPasswords" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "IncognitoModeAvailability" /t REG_DWORD /d "16777216" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "EnableOnlineRevocationChecks" /t REG_DWORD /d "16777216" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "SavingBrowserHistoryDisabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultPluginsSetting" /t REG_DWORD /d "50331648" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "AllowDeletingBrowserHistory" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "PromptForDownloadLocation" /t REG_DWORD /d "16777216" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "DownloadRestrictions" /t REG_DWORD /d "33554432" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "AutoplayAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "SafeBrowsingExtendedReportingEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultWebUsbGuardSetting" /t REG_DWORD /d "33554432" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "EnableMediaRouter" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d "tls1.1" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "UrlKeyedAnonymizedDataCollectionEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "WebRtcEventLogCollectionAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "NetworkPredictionOptions" /t REG_DWORD /d "33554432" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "BrowserGuestModeEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome" /v "ImportAutofillFormData" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Google\Chrome\ExtensionInstallWhitelist" /v "1" /t REG_SZ /d "cjpalhdlnbpafiamejdnhcphjbkeiagm" /f
reg add "HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist" /v "1" /t REG_SZ /d "cjpalhdlnbpafiamejdnhcphjbkeiagm" /f
reg add "HKLM\Software\Policies\Google\Chrome\URLBlacklist" /v "1" /t REG_SZ /d "javascript://*" /f
reg add "HKLM\Software\Policies\Google\Update" /v "AutoUpdateCheckPeriodMinutes" /t REG_DWORD /d "1613168640" /f
reg add "HKLM\Software\Policies\Google\Chrome\Recommended" /v "SafeBrowsingProtectionLevel" /t REG_DWORD /d "2" /f

BCDEDIT /set nointegritychecks OFF
:: "BCDEDIT" is like a magic wand for managing your boot settings, and "/set nointegritychecks OFF" is a spell that tells Windows to start checking driver integrity again and enforce device driver signing.
::
::###############################################################################################################
:: Credits and More info: https://gist.github.com/mackwage/08604751462126599d7e52f233490efe
::                        https://github.com/LOLBAS-Project/LOLBAS
::                        https://lolbas-project.github.io/
::                        https://github.com/Disassembler0/Win10-Initial-Setup-Script
::                        https://github.com/cryps1s/DARKSURGEON/tree/master/configuration/configuration-scripts
::                        https://gist.github.com/alirobe/7f3b34ad89a159e6daa1#file-reclaimwindows10-ps1-L71
::                        https://github.com/teusink/Home-Security-by-W10-Hardening
::                        https://gist.github.com/ricardojba/ecdfe30dadbdab6c514a530bc5d51ef6
::                        https://github.com/atlantsecurity/windows-hardening-scripts/blob/main/windows-11-hardening-script
::                        https://www.greyhathacker.net/?p=235
::                        https://www.verifyit.nl/wp/?p=175464
::                        https://support.microsoft.com/en-us/help/2264107/a-new-cwdillegalindllsearch-registry-entry-is-available-to-control-the
::
::###############################################################################################################
::###############################################################################################################
