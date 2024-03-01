rule SIGNATURE_BASE_EXPL_CVE_2024_21413_Microsoft_Outlook_RCE_Feb24 : CVE_2024_21413 FILE
{
	meta:
		description = "Detects emails that contain signs of a method to exploit CVE-2024-21413 in Microsoft Outlook"
		author = "Florian Roth"
		id = "bc8805a8-ae29-5e9a-9cbc-bcc46fb99afc"
		date = "2024-02-17"
		modified = "2024-02-17"
		reference = "https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/expl_outlook_cve_2024_21413.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ffdcaba66d14d51b66b1f122b7d59c75d3aab65f0746aa5d13bc042b1c3a2077"
		score = 75
		quality = 85
		tags = "CVE-2024-21413, FILE"

	strings:
		$a1 = "Subject: "
		$a2 = "Received: "
		$xr1 = /href[\s=3D"']{2,20}file:\/\/\/\\\\[^"']{6,200}!/

	condition:
		filesize <800KB and all of ($a*) and 1 of ($xr*)
}
