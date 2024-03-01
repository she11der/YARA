rule SIGNATURE_BASE_Impacket_Tools_Wmiexec : FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "3c2c7edf-da71-53dc-9ddf-dfbf10838a27"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L28-L43"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "1ac78768ae230aa00f392f7a7886589b14814e9c7379528d2ecd218852086ee4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "19544863758341fe7276c59d85f4aa17094045621ca9c98f8a9e7307c290bad4"

	strings:
		$s1 = "bwmiexec.exe.manifest" fullword ascii
		$s2 = "swmiexec" fullword ascii
		$s3 = "\\yzHPlU=QA" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and 2 of them )
}
