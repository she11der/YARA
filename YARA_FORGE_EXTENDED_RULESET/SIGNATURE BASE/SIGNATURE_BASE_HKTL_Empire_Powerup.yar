rule SIGNATURE_BASE_HKTL_Empire_Powerup : FILE
{
	meta:
		description = "Detects Empire component - file PowerUp.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "e79d093e-7481-52a3-a350-4d1b6d8955cd"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L109-L122"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "d55674866a1a14d4f4c2b5529e47e005ca4b433383bf112af6da41d7f84afdb7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"

	strings:
		$x2 = "$PoolPasswordCmd = 'c:\\windows\\system32\\inetsrv\\appcmd.exe list apppool" fullword ascii

	condition:
		( uint16(0)==0x233c and filesize <2000KB and 1 of them ) or all of them
}
