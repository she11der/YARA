rule SIGNATURE_BASE_Impacket_Tools_Rpcdump : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "3f998aa6-c260-5fef-99ef-e8b4770c68c6"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_impacket_tools.yar#L124-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "cf0a64391ef0a5d3f87996fb3e4f152a3ff4938356b96f840aa3f4f4f30aaa97"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "21d85b36197db47b94b0f4995d07b040a0455ebbe6d413bc33d926ee4e0315d9"

	strings:
		$s1 = "srpcdump" fullword ascii
		$s2 = "impacket.dcerpc.v5.epm(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
