rule SIGNATURE_BASE_Empire_Invoke_Smbautobrute : FILE
{
	meta:
		description = "Detects Empire component - file Invoke-SMBAutoBrute.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "a6b402ac-0925-5bc6-9d6a-b2b811496f9e"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L291-L305"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "dd87a5d3a710017953c8c19862e4daee25de0e57175cab8246eea6d067fcb4d1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7950f8abdd8ee09ed168137ef5380047d9d767a7172316070acc33b662f812b2"

	strings:
		$s1 = "[*] PDC: LAB-2008-DC1.lab.com" fullword ascii
		$s2 = "$attempts = Get-UserBadPwdCount $userid $dcs" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <30KB and 1 of them ) or all of them
}
