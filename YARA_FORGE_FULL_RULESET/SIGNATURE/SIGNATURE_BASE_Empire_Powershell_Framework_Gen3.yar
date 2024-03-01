rule SIGNATURE_BASE_Empire_Powershell_Framework_Gen3 : FILE
{
	meta:
		description = "Detects Empire component"
		author = "Florian Roth (Nextron Systems)"
		id = "b0f7ed41-be65-5e43-aeb1-56e5e7384e8f"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L449-L467"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "933fe27c54e90806a21082b4d2e4cbb3491374e48834a64c0d6a520c537d145e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
		hash2 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
		hash3 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
		hash4 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"

	strings:
		$s1 = "if (($PEInfo.FileType -ieq \"DLL\") -and ($RemoteProcHandle -eq [IntPtr]::Zero))" fullword ascii
		$s2 = "remote DLL injection" ascii

	condition:
		( uint16(0)==0x7566 and filesize <4000KB and 1 of them ) or all of them
}
