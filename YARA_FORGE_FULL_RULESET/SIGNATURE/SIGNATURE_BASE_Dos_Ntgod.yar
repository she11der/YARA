rule SIGNATURE_BASE_Dos_Ntgod : FILE
{
	meta:
		description = "Chinese Hacktool Set - file NtGod.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "c2f0733d-5519-5cb8-b077-0ae8472400b4"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1858-L1874"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "adefd901d6bbd8437116f0170b9c28a76d4a87bf"
		logic_hash = "77b9204add5d25dcc36eabc07cabea2bdc67a23873c2faf7706e7fba5ed53f8b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\temp\\NtGodMode.exe" ascii
		$s4 = "NtGodMode.exe" fullword ascii
		$s10 = "ntgod.bat" fullword ascii
		$s19 = "sfxcmd" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <250KB and all of them
}
