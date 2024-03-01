rule SIGNATURE_BASE_Empire_Get_Securitypackages : FILE
{
	meta:
		description = "Detects Empire component - file Get-SecurityPackages.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "a109eda1-a26d-5cf6-b6b5-1a1a1e770a0a"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L43-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2d63fdcc6713d2f7645b16cf3e79a6e951c7751a10bfa0e2853def47ea9547d2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5d06e99121cff9b0fce74b71a137501452eebbcd1e901b26bde858313ee5a9c1"

	strings:
		$s1 = "$null = $EnumBuilder.DefineLiteral('LOGON', 0x2000)" fullword ascii
		$s2 = "$EnumBuilder = $ModuleBuilder.DefineEnum('SSPI.SECPKG_FLAG', 'Public', [Int32])" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <20KB and 1 of them ) or all of them
}
