rule SIGNATURE_BASE_Clearlog : FILE
{
	meta:
		description = "Detects Fireball malware - file clearlog.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "3eb58a7a-b04d-52c2-8c3c-c149da8d4aa8"
		date = "2017-06-02"
		modified = "2023-12-05"
		reference = "https://goo.gl/4pTkGQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_fireball.yar#L151-L171"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "6b6fd74ad184cafa7885385f808034e9211ff37e04ed5e8ea4af2c7fb7d697bd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "14093ce6d0fe8ab60963771f48937c669103842a0400b8d97f829b33c420f7e3"

	strings:
		$x1 = "\\ClearLog\\Release\\logC.pdb" ascii
		$s1 = "C:\\Windows\\System32\\cmd.exe /c \"\"" fullword wide
		$s2 = "logC.dll" fullword ascii
		$s3 = "hhhhh.exe" fullword wide
		$s4 = "ttttt.exe" fullword wide
		$s5 = "Logger Name:" fullword ascii
		$s6 = "cle.log.1" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and $x1 or 2 of them )
}
