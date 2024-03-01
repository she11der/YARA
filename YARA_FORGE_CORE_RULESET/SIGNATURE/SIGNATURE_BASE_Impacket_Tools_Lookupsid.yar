rule SIGNATURE_BASE_Impacket_Tools_Lookupsid : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "27f13397-b044-54b4-b5e8-c5f7ed374f59"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L321-L335"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "629ddd49377017d6ea2aac9665b21dfdf9a50c917bf915ea892faafd841bf817"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "47756725d7a752d3d3cfccfb02e7df4fa0769b72e008ae5c85c018be4cf35cc1"

	strings:
		$s1 = "slookupsid" fullword ascii
		$s2 = "impacket.dcerpc" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and all of them )
}
