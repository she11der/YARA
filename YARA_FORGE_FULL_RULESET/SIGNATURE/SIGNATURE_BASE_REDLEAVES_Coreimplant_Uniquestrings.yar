rule SIGNATURE_BASE_REDLEAVES_Coreimplant_Uniquestrings
{
	meta:
		description = "Strings identifying the core REDLEAVES RAT in its deobfuscated state"
		author = "USG"
		id = "fd4d4804-f7d9-549d-8f63-5f409d6180f9"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_uscert_ta17-1117a.yar#L49-L61"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "40bd783fe7cdeb0dda61cc1c38f5b4f6d9c63b6051dc2ede24ae5e88cd173a25"
		score = 75
		quality = 81
		tags = ""

	strings:
		$unique2 = "RedLeavesSCMDSimulatorMutex" nocase wide ascii
		$unique4 = "red_autumnal_leaves_dllmain.dll" wide ascii
		$unique7 = "\\NamePipe_MoreWindows" wide ascii

	condition:
		any of them
}
