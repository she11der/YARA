rule SIGNATURE_BASE_Empire_Powershell_Framework_Gen5 : FILE
{
	meta:
		description = "Detects Empire component"
		author = "Florian Roth (Nextron Systems)"
		id = "4c23592e-5788-5b84-995a-028142cbc52f"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L584-L601"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "115fffabb09ed00ab46c6f980c3a7727070a303cafa900cc1ce04e3999b6b70e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
		hash2 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
		hash3 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"

	strings:
		$s1 = "if ($ExeArgs -ne $null -and $ExeArgs -ne '')" fullword ascii
		$s2 = "$ExeArgs = \"ReflectiveExe $ExeArgs\"" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <1000KB and 1 of them ) or all of them
}
