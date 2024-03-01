rule SIGNATURE_BASE_CN_Honker_Clearlogs : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file clearlogs.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bfbc339e-5530-5984-94de-be1002f09ca1"
		date = "2015-06-23"
		modified = "2023-01-27"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1720-L1736"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "490f3bc318f415685d7e32176088001679b0da1b"
		logic_hash = "ed961d2850ba86743177976a4516e7d4a8b90b7e8f180c03f5dbbcc794ad1084"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "- http://ntsecurity.nu/toolbox/clearlogs/" ascii
		$s4 = "Error: Unable to clear log - " fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <140KB and all of them
}
