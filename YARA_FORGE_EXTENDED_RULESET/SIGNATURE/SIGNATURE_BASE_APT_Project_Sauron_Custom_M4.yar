rule SIGNATURE_BASE_APT_Project_Sauron_Custom_M4 : FILE
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "Florian Roth (Nextron Systems)"
		id = "32717ace-ff56-5b5b-8ed9-4bb353886eea"
		date = "2016-08-09"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_project_sauron_extras.yar#L188-L206"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0735ba9591a9cf06cd13ba480b4559ef83105ab08ffcec21ebbbfdf3766edb93"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e12e66a6127cfd2cbb42e6f0d57c9dd019b02768d6f1fb44d91f12d90a611a57"

	strings:
		$s1 = "xpsmngr.dll" fullword wide
		$s2 = "XPS Manager" fullword wide
		$op0 = { 89 4d e8 89 4d ec 89 4d f0 ff d2 3d 08 00 00 c6 }
		$op1 = { 55 8b ec ff 4d 0c 75 09 ff 75 08 ff 15 04 20 5b }
		$op2 = { 8b 4f 06 85 c9 74 14 83 f9 13 0f 82 b6 }

	condition:
		( uint16(0)==0x5a4d and filesize <90KB and ( all of ($s*)) and 1 of ($op*)) or ( all of them )
}
