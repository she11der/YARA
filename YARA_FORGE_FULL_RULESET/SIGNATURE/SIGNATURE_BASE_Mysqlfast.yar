rule SIGNATURE_BASE_Mysqlfast : FILE
{
	meta:
		description = "Chinese Hacktool Set - file mysqlfast.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "93ee91cd-a6b8-5ed9-b750-779f88032be6"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L141-L159"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "32b60350390fe7024af7b4b8fbf50f13306c546f"
		logic_hash = "3ea75954831e705d0d25efa115288e66868d9b814f0990fd048bbe1209a8d933"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Invalid password hash: %s" fullword ascii
		$s3 = "-= MySql Hash Cracker =- " fullword ascii
		$s4 = "Usage: %s hash" fullword ascii
		$s5 = "Hash: %08lx%08lx" fullword ascii
		$s6 = "Found pass: " fullword ascii
		$s7 = "Pass not found" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and 4 of them
}
