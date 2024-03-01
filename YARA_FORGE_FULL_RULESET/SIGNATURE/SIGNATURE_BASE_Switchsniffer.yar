rule SIGNATURE_BASE_Switchsniffer : FILE
{
	meta:
		description = "Chinese Hacktool Set - file SwitchSniffer.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "6019f042-10ab-5899-8b1b-28b2609e9623"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L640-L654"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1e7507162154f67dff4417f1f5d18b4ade5cf0cd"
		logic_hash = "4c75473399a7d47b63c6247248fd2792c675740ac671028b1c0a8ba1a02f35aa"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "NextSecurity.NET" fullword wide
		$s2 = "SwitchSniffer Setup" fullword wide

	condition:
		uint16(0)==0x5a4d and all of them
}
