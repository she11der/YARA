rule SIGNATURE_BASE_Impacket_Tools_Esentutl___FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "1965e2b3-54be-553a-83d6-a0d4919414dd"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L156-L170"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e972ad610df65309f4e5996ad0b537670b944f43b810fda5a890ea995193a97a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "70d854953d3ebb2c252783a4a103ba0e596d6ab447f238af777fb37d2b64c0cd"

	strings:
		$s1 = "impacket.ese(" ascii
		$s2 = "sesentutl" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <11000KB and all of them )
}