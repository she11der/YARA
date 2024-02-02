rule SIGNATURE_BASE_APT_UA_Hermetic_Wiper_Scheduled_Task_Feb22_1
{
	meta:
		description = "Detects scheduled task pattern found in Hermetic Wiper malware related intrusions"
		author = "Florian Roth (Nextron Systems)"
		id = "a628f773-9c71-5979-a4db-37b6b6bd6a56"
		date = "2022-02-25"
		modified = "2023-12-05"
		reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_ua_hermetic_wiper.yar#L72-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "56368ba1c97fe3455312b6ee86dcd1a21677f7dfa3836e76ada4b236a5b2c171"
		score = 85
		quality = 85
		tags = ""

	strings:
		$a0 = "<Task version=" ascii wide
		$sa1 = "CSIDL_SYSTEM_DRIVE\\temp" ascii wide
		$sa2 = "postgresql.exe 1> \\\\127.0.0.1\\ADMIN$" ascii wide
		$sa3 = "cmd.exe /Q /c move CSIDL_SYSTEM_DRIVE" ascii wide

	condition:
		$a0 and 1 of ($s*)
}