rule SIGNATURE_BASE_Impacket_Tools_Secretsdump : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "c944d051-ea24-5595-abef-59e326ad56de"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L140-L154"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "462748d60764c6fbaeede48b5a98cb68f61cf695f976bf6db94cb497be48fcb2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "47afa5fd954190df825924c55112e65fd8ed0f7e1d6fd403ede5209623534d7d"

	strings:
		$s1 = "ssecretsdump" fullword ascii
		$s2 = "impacket.ese(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}
