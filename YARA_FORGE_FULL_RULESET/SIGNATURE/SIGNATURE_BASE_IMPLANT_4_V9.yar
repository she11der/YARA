import "pe"

rule SIGNATURE_BASE_IMPLANT_4_V9
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		id = "a404212a-d9ef-54c1-bbf8-a213ec094f18"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L913-L933"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c0e48bf0839965f9bda9cc475aba5b4934c27c426a8fa4423fb24aa9d792e2e4"
		score = 85
		quality = 77
		tags = ""

	strings:
		$a = "wevtutil clear-log" ascii wide nocase
		$b = "vssadmin delete shadows" ascii wide nocase
		$c = "AGlobal\\23d1a259-88fa-41df-935f-cae523bab8e6" ascii wide nocase
		$d = "Global\\07fd3ab3-0724-4cfd-8cc2-60c0e450bb9a" ascii wide nocase
		$openPhysicalDiskOverwriteWithZeros = { 57 55 33 C9 51 8B C3 99 57 52
         50 E8 ?? ?? ?? ?? 52 50 E8 ?? ?? ?? ?? 83 C4 10 84 C0 75 21 33 C0 89
         44 24 10 89 44 24 14 6A 01 8B C7 99 8D 4C 24 14 51 52 50 56 FF 15 ??
         ?? ?? ?? 85 C0 74 0B 83 C3 01 81 FB 00 01 00 00 7C B6 }
		$f = {83 c4 0c 53 53 6a 03 53 6a 03 68 00 00 00 c0}

	condition:
		($a and $b) or $c or $d or ($openPhysicalDiskOverwriteWithZeros and $f)
}
