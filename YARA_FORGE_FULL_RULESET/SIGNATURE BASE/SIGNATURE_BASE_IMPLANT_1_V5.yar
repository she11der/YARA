import "pe"

rule SIGNATURE_BASE_IMPLANT_1_V5 : FILE
{
	meta:
		description = "Downrage Implant by APT28"
		author = "US CERT"
		id = "ac1c6175-3a8b-524b-bb18-243c52f7dba1"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L75-L91"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e9660dfe76bfe1eb17b434f2ddef4975495e952396212c41550d932dbb8e8205"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$drivername = { 6A 30 ?? 6A 33 [5] 6A 37 [5] 6A 32 [5] 6A 31 [5] 6A 77
         [5] 6A 69 [5] 6A 6E [5] 6A 2E [5] 6A 73 [5-9] 6A 79 [5] 6A 73 }
		$mutexname = { C7 45 ?? 2F 2F 64 66 C7 45 ?? 63 30 31 65 C7 45 ?? 6C 6C
         36 7A C7 45 ?? 73 71 33 2D C7 45 ?? 75 66 68 68 66 C7 45 ?? 66 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and any of them
}
