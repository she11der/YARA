rule SIGNATURE_BASE_Impacket_Tools_Smbtorture___FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "4f9b55e2-93ce-5d08-a228-73233fb0a2c6"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L254-L268"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "63cbd6511c5498b39fa5efadb8fe0caeeaa8d4c2afe534a0169ea38f205a9cba"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d2856e98011541883e5b335cb46b713b1a6b2c414966a9de122ee7fb226aa7f7"

	strings:
		$s1 = "impacket" fullword ascii
		$s2 = "ssmbtorture" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}