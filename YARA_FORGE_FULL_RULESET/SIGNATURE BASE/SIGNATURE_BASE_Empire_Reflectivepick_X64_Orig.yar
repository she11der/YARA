rule SIGNATURE_BASE_Empire_Reflectivepick_X64_Orig : FILE
{
	meta:
		description = "Detects Empire component - file ReflectivePick_x64_orig.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "cd69a149-d881-5f93-9647-84241bd96ba5"
		date = "2016-11-05"
		modified = "2022-12-21"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L224-L240"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a87c5f1da9c490887cba5e9837ca40ac92b63d8c36b682f4be770ac061b5acdf"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "a8c1b108a67e7fc09f81bd160c3bafb526caf3dbbaf008efb9a96f4151756ff2"

	strings:
		$a1 = "\\PowerShellRunner.pdb" ascii
		$a2 = "PowerShellRunner.dll" fullword wide
		$s1 = "ReflectivePick" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 1 of ($a*) and $s1
}
