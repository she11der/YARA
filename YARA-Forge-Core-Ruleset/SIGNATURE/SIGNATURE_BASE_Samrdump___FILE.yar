rule SIGNATURE_BASE_Samrdump___FILE
{
	meta:
		description = "Compiled Impacket Tools"
		author = "Florian Roth (Nextron Systems)"
		id = "cd274719-c8cc-5882-8d75-192ad822c6b3"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_impacket_tools.yar#L108-L122"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "6bc0a4d9f9bd0d72e7f2ce4b0f8608296e6f2db14fd3a1740e0eebfe35629018"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4c2921702d18e0874b57638433474e54719ee6dfa39d323839d216952c5c834a"

	strings:
		$s2 = "bsamrdump.exe.manifest" fullword ascii
		$s3 = "ssamrdump" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <17000KB and all of them )
}