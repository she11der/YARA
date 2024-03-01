rule SIGNATURE_BASE_EXT_NK_GOLDBACKDOOR_Inital_Shellcode
{
	meta:
		description = "Detection for initial shellcode loader used to deploy GOLDBACDOOR"
		author = "Silas Cutler (silas@Stairwell.com)"
		id = "daab8e54-11b3-51cc-8bee-55b078f3e791"
		date = "2022-04-21"
		modified = "2023-12-05"
		reference = "https://stairwell.com/wp-content/uploads/2022/04/Stairwell-threat-report-The-ink-stained-trail-of-GOLDBACKDOOR.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_nk_goldbackdoor.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4df97181037a580098dbe34d3b6ceab5c7b83932f1831c36ee99876a8f1524f9"
		score = 80
		quality = 85
		tags = ""
		version = "0.1"

	strings:
		$ = { C7 45 C4 25 6C 6F 63 50 8D 45 C4 C7 45 C8 61 6C 61 70 8B F9 C7 45
              CC 70 64 61 74 50 B9 BD 88 17 75 C7 45 D0 61 25 5C 6C 8B DA C7 45 D4 6F
              67 5F 67 C7 45 D8 6F 6C 64 2E C7 45 DC 74 78 74 00 }
		$ = { 51 50 57 56 B9 E6 8E 85 35 E8 ?? ?? ?? ?? FF D0 }
		$ = { 6A 40 68 00 10 00 00 52 6A 00 FF 75 E0 B9 E3 18 90 72 E8 ?? ?? ?? ?? FF D0}

	condition:
		all of them
}
