rule SIGNATURE_BASE_Impacket_Tools_Opdump___FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "1bb0e747-e9b7-5a54-8052-428351be8d0d"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L172-L186"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "18b772e19fd61d77f3a671ee097e0f032738a73a360f4cfe79df4eb6377e12b1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e2205539f29972d4e2a83eabf92af18dd406c9be97f70661c336ddf5eb496742"

	strings:
		$s2 = "bopdump.exe.manifest" fullword ascii
		$s3 = "sopdump" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}