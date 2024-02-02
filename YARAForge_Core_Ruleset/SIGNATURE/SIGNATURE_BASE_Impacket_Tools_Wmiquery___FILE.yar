rule SIGNATURE_BASE_Impacket_Tools_Wmiquery___FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "e8bdf27a-9763-5947-854f-162f74ff53be"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L337-L351"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "fa237b5c1b4881804c33152a1ce9f3a571b506178fde455a8dd9f92af68c5610"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "202a1d149be35d96e491b0b65516f631f3486215f78526160cf262d8ae179094"

	strings:
		$s1 = "swmiquery" fullword ascii
		$s2 = "\\yzHPlU=QA" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}