rule SIGNATURE_BASE_Chrome_Elf : FILE
{
	meta:
		description = "Detects Fireball malware - file chrome_elf.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "8680d5b5-e26f-5a3f-aeab-b965afe91027"
		date = "2017-06-02"
		modified = "2023-12-05"
		reference = "https://goo.gl/4pTkGQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_fireball.yar#L72-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "89f0ab16f164222ecf2a4b14bee02d0c24517d03d1c12b25f5158eebc31b3e3d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e4d4f6fbfbbbf3904ca45d296dc565138a17484c54aebbb00ba9d57f80dfe7e5"

	strings:
		$x2 = "schtasks /Create /SC HOURLY /MO %d /ST 00:%02d:00 /TN \"%s\" /TR \"%s\" /RU \"SYSTEM\"" fullword wide
		$s6 = "aHR0cDovL2R2Mm0xdXVtbnNndHUuY2xvdWRmcm9udC5uZXQvdjQvZ3RnLyVzP2FjdGlvbj12aXNpdC5jaGVsZi5pbnN0YWxs" fullword ascii
		$s7 = "QueryInterface call failed for IExecAction: %x" fullword ascii
		$s10 = "%s %s,Rundll32_Do %s" fullword wide
		$s13 = "Failed to create an instance of ITaskService: %x" fullword ascii
		$s16 = "Rundll32_Do" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 4 of them )
}
