rule SIGNATURE_BASE_APT_Project_Sauron_Custom_M2 : FILE
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "Florian Roth (Nextron Systems)"
		id = "79abe5f2-a750-5018-a67f-6ee1c51a2ca1"
		date = "2016-08-09"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_project_sauron_extras.yar#L150-L167"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "57099a802ee62a5183156f0b30713553b6fd83bbb5e1b453e9b25da0109b8777"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "30a824155603c2e9d8bfd3adab8660e826d7e0681e28e46d102706a03e23e3a8"

	strings:
		$s2 = "\\*\\3vpn" ascii
		$op0 = { 55 8b ec 83 ec 0c 53 56 33 f6 39 75 08 57 89 75 }
		$op1 = { 59 59 c3 8b 65 e8 ff 75 88 ff 15 50 20 40 00 ff }
		$op2 = { 8b 4f 06 85 c9 74 14 83 f9 12 0f 82 a7 }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and ( all of ($s*)) and all of ($op*))
}
