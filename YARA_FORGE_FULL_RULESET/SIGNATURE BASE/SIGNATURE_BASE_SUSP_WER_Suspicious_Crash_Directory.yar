rule SIGNATURE_BASE_SUSP_WER_Suspicious_Crash_Directory : FILE
{
	meta:
		description = "Detects a crashed application executed in a suspicious directory"
		author = "Florian Roth (Nextron Systems)"
		id = "bf91e20c-aa35-5b13-86ed-a63e6fb4d1a2"
		date = "2019-10-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1185585050059976705"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_wer_files.yar#L20-L54"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a197feeafca38ffe33428fa807e2b80e3071ab8960926fc2f328748bda299910"
		score = 45
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "ReportIdentifier=" wide
		$a2 = ".Name=Fault Module Name" wide
		$a3 = "AppPath=" wide nocase
		$l1 = "AppPath=C:\\Windows\\" wide nocase
		$l2 = "AppPath=C:\\Program" wide nocase
		$l3 = "AppPath=C:\\Python" wide nocase
		$l4 = "AppPath=C:\\Users\\" wide nocase
		$s6 = "AppPath=C:\\Users\\Public\\" nocase wide
		$s7 = "AppPath=C:\\Users\\Default\\" nocase wide
		$s8 = /AppPath=C:\\Users\\[^\\]{1,64}\\AppData\\(Local|Roaming)\\[^\\]{1,64}\.exe/ wide nocase

	condition:
		( uint32be(0)==0x56006500 or uint32be(0)==0xfffe5600) and all of ($a*) and ( not 1 of ($l*) or 1 of ($s*))
}
