rule TELEKOM_SECURITY_Win_Iceid_Gzip_Ldr_202104 : FILE
{
	meta:
		description = "2021 initial Bokbot / Icedid loader for fake GZIP payloads"
		author = "Thomas Barabosch, Telekom Security"
		id = "9d905e90-dfec-596b-bd09-72413df49345"
		date = "2021-04-12"
		modified = "2021-07-08"
		reference = "https://github.com/telekom-security/malware_analysis/"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/icedid/icedid_20210507.yar#L14-L38"
		license_url = "N/A"
		logic_hash = "caf997e623920a230acce8a7256516aceb6a587823e0525a17e5d69d0ed45d12"
		score = 75
		quality = 45
		tags = "FILE"

	strings:
		$internal_name = "loader_dll_64.dll" fullword
		$string0 = "_gat=" wide
		$string1 = "_ga=" wide
		$string2 = "_gid=" wide
		$string3 = "_u=" wide
		$string4 = "_io=" wide
		$string5 = "GetAdaptersInfo" fullword
		$string6 = "WINHTTP.dll" fullword
		$string7 = "DllRegisterServer" fullword
		$string8 = "PluginInit" fullword
		$string9 = "POST" wide fullword
		$string10 = "aws.amazon.com" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and ($internal_name or all of ($s*)) or all of them
}
