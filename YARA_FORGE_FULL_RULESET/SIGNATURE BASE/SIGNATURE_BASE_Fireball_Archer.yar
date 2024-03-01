rule SIGNATURE_BASE_Fireball_Archer : FILE
{
	meta:
		description = "Detects Fireball malware - file archer.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "16bb95c1-af69-5688-8999-f097d02d2ffc"
		date = "2017-06-02"
		modified = "2022-12-21"
		reference = "https://goo.gl/4pTkGQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_fireball.yar#L130-L149"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f566ba477ccf1325914b6c9785e2b85f732b211e9321eea24d6c5a0339ccc4d1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022"

	strings:
		$x1 = "\\archer_lyl\\Release\\Archer_Input.pdb" ascii
		$s1 = "Archer_Input.dll" fullword ascii
		$s2 = "InstallArcherSvc" fullword ascii
		$s3 = "%s_%08X" fullword wide
		$s4 = "d\\\\.\\PhysicalDrive%d" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and ($x1 or 3 of them )
}
