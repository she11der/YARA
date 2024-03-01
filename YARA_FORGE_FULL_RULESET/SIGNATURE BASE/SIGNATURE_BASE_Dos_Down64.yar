rule SIGNATURE_BASE_Dos_Down64 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Down64.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b4907ede-dc6a-5b8c-bf1c-557df54191a4"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1197-L1215"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "43e455e43b49b953e17a5b885ffdcdf8b6b23226"
		logic_hash = "d181c2075762fc3bb5b61bcdef57eb6533cb59dde03c4b901b6ce5b8323f3c8a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "C:\\Windows\\Temp\\Down.txt" fullword wide
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s3 = "C:\\Windows\\Temp\\" wide
		$s4 = "ProcessXElement" fullword ascii
		$s8 = "down.exe" fullword wide
		$s20 = "set_Timer1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <150KB and all of them
}
