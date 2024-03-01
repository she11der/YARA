rule SIGNATURE_BASE_APT_UA_Hermetic_Wiper_Artefacts_Feb22_1
{
	meta:
		description = "Detects artefacts found in Hermetic Wiper malware related intrusions"
		author = "Florian Roth (Nextron Systems)"
		id = "77f793c1-b02c-59c3-b3e4-75758f5b3b8d"
		date = "2022-02-25"
		modified = "2023-12-05"
		reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_ua_hermetic_wiper.yar#L40-L70"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5e917618a5172c68b4b32ba9e63402c2a98ccb027276b317ec169a4fef219de1"
		score = 75
		quality = 85
		tags = ""

	strings:
		$sx1 = "/c powershell -c \"rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump" ascii wide
		$sx2 = "appdata\\local\\microsoft\\windows\\winupd.log" ascii wide
		$sx3 = "AppData\\Local\\Microsoft\\Windows\\Winupd.log" ascii wide
		$sx4 = "CSIDL_SYSTEM_DRIVE\\temp\\sys.tmp1" ascii wide
		$sx5 = "\\policydefinitions\\postgresql.exe" ascii wide
		$sx6 = "powershell -v 2 -exec bypass -File text.ps1" ascii wide
		$sx7 = "powershell -exec bypass gp.ps1" ascii wide
		$sx8 = "powershell -exec bypass -File link.ps1" ascii wide
		$sx9 = " 1> \\\\127.0.0.1\\ADMIN$\\__16" ascii wide
		$sa1 = "(New-Object System.Net.WebClient).DownloadFile(" ascii wide
		$sa2 = "CSIDL_SYSTEM_DRIVE\\temp\\" ascii wide
		$sa3 = "1> \\\\127.0.0.1\\ADMIN$" ascii wide
		$fp1 = "<html" ascii

	condition:
		1 of ($sx*) or all of ($sa*) and not 1 of ($fp*)
}
