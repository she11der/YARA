import "pe"

rule SIGNATURE_BASE_QQ_Zip_Folder_QQ
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file QQ.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "30da6292-f670-5b73-985a-3028e20607be"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2019-L2039"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9f8e3f40f1ac8c1fa15a6621b49413d815f46cfb"
		logic_hash = "d2517c3646b9a3babfa767c5c57b4b576fda471c190ab66e1054c4de359713ad"
		score = 60
		quality = 35
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "EMAIL:haoq@neusoft.com" fullword wide
		$s1 = "EMAIL:haoq@neusoft.com" fullword wide
		$s4 = "QQ2000b.exe" fullword wide
		$s5 = "haoq@neusoft.com" fullword ascii
		$s9 = "QQ2000b.exe" fullword ascii
		$s10 = "\\qq2000b.exe" ascii
		$s12 = "WINDSHELL STUDIO[WINDSHELL " fullword wide
		$s17 = "SOFTWARE\\HAOQIANG\\" ascii

	condition:
		5 of them
}
