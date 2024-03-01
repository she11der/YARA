rule SIGNATURE_BASE_Codoso_Customtcp_2 : FILE
{
	meta:
		description = "Detects Codoso APT CustomTCP Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "b6ed6939-db0c-5a47-8839-3337d1bc1f6c"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_codoso.yar#L94-L114"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3577845d71ae995762d4a8f43b21ada49d809f95c127b770aff00ae0b64264a3"
		logic_hash = "a355ac60dca5ca880a90a5c2720690b4691630fd434411758fa7ff006f7389ba"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "varus_service_x86.dll" fullword ascii
		$s2 = "/s %s /p %d /st %d /rt %d" fullword ascii
		$s3 = "net start %%1" fullword ascii
		$s4 = "ping 127.1 > nul" fullword ascii
		$s5 = "McInitMISPAlertEx" fullword ascii
		$s6 = "sc start %%1" fullword ascii
		$s7 = "B_WKNDNSK^" fullword ascii
		$s8 = "net stop %%1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <406KB and all of them
}
