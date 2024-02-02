rule SIGNATURE_BASE_Impacket_Tools_Smbrelayx___FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "84abf3cf-841c-592d-a9d1-71d5e76eb43f"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L287-L303"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "2afcede9d9f5af102c68e705f29242bc3a56485e79c0acfc347a4ea7f823dfda"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9706eb99e48e445ac4240b5acb2efd49468a800913e70e40b25c2bf80d6be35f"

	strings:
		$s1 = "impacket.examples.secretsdump" fullword ascii
		$s2 = "impacket.examples.serviceinstall" fullword ascii
		$s3 = "impacket.smbserver(" ascii
		$s4 = "SimpleHTTPServer(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <18000KB and 3 of them )
}