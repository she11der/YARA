rule SIGNATURE_BASE_Codoso_Customtcp : FILE
{
	meta:
		description = "Codoso CustomTCP Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "b6ed6939-db0c-5a47-8839-3337d1bc1f6c"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_codoso.yar#L171-L188"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b95d7f56a686a05398198d317c805924c36f3abacbb1b9e3f590ec0d59f845d8"
		logic_hash = "4f0333de25b9f84ecaa3e63c5f600f53929244cd63a681d21cb78cfe17ca15f9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "wnyglw" fullword ascii
		$s5 = "WorkerRun" fullword ascii
		$s7 = "boazdcd" fullword ascii
		$s8 = "wayflw" fullword ascii
		$s9 = "CODETABL" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <405KB and all of them
}
