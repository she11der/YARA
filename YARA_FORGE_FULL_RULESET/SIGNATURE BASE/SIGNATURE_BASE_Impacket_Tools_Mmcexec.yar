rule SIGNATURE_BASE_Impacket_Tools_Mmcexec : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "cca2082f-72a4-50c8-80b8-a9bed430dc4e"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_impacket_tools.yar#L61-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1aee75155ed3d868f576d7d650f0791ac54e351851f7bfb65390b4ae5c4c83b9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "263a1655a94b7920531e123a8c9737428f2988bf58156c62408e192d4b2a63fc"

	strings:
		$s1 = "smmcexec" fullword ascii
		$s2 = "\\yzHPlU=QA" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <16000KB and all of them )
}
