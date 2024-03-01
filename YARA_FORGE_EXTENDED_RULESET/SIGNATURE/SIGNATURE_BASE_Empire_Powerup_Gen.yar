rule SIGNATURE_BASE_Empire_Powerup_Gen : FILE
{
	meta:
		description = "Detects Empire component - from files PowerUp.ps1, PowerUp.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "ae6b0462-7193-54a4-8fb9-befc1b461b15"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L392-L407"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4086b057b46cac85bb871d2d4363d4ae4c99a160e5c9625e4d41e3df55fece2d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"

	strings:
		$s1 = "$Result = sc.exe config $($TargetService.Name) binPath= $OriginalPath" fullword ascii
		$s2 = "$Result = sc.exe pause $($TargetService.Name)" fullword ascii

	condition:
		( uint16(0)==0x233c and filesize <2000KB and 1 of them ) or all of them
}
