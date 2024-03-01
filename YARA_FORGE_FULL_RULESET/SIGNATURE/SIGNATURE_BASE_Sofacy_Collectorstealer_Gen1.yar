rule SIGNATURE_BASE_Sofacy_Collectorstealer_Gen1 : FILE
{
	meta:
		description = "Generic rule to detect Sofacy Malware Collector Stealer"
		author = "Florian Roth (Nextron Systems)"
		id = "f9462dd9-f6b6-59f4-a443-12d6f3be444e"
		date = "2015-12-04"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sofacy_dec15.yar#L80-L97"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1b6693fa45fed5ed001d8fb4b43427c7036d95cb36b125e7242864d000085018"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "4e4606313c423b681e11110ca5ed3a2b2632ec6c556b7ab9642372ae709555f3"
		hash2 = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"

	strings:
		$s0 = "NvCpld.dll" fullword ascii
		$s1 = "NvStop" fullword ascii
		$s2 = "NvStart" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
