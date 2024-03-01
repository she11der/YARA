rule SIGNATURE_BASE_HKTL_CN_Dos_Sys : FILE
{
	meta:
		description = "Chinese Hacktool Set - file sys.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c4b740f2-f4f8-59ff-ad1f-c06718040b50"
		date = "2015-06-13"
		modified = "2023-01-06"
		old_rule_name = "Dos_sys"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L860-L878"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b5837047443f8bc62284a0045982aaae8bab6f18"
		logic_hash = "3b3f55c45ebfe4ab6d8e6b06a3c452c84d4f755f984d913c683a49a8fd570d9d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "'SeDebugPrivilegeOpen " fullword ascii
		$s6 = "Author: Cyg07*2" fullword ascii
		$s12 = "from golds7n[LAG]'J" fullword ascii
		$s14 = "DAMAGE" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <150KB and all of them
}
