rule SIGNATURE_BASE_Dos_Down32 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Down32.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "e56c254d-1238-5786-8e8a-f9122b0310a9"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L493-L508"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0365738acd728021b0ea2967c867f1014fd7dd75"
		logic_hash = "c1aaaaaaae2ea720d3fc1516d88d678895bcda81344e8c1f4f57e5a20e770123"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s6 = "down.exe" fullword wide
		$s15 = "get_Form1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <137KB and all of them
}
