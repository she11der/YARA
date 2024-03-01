import "pe"

rule SIGNATURE_BASE_IMPLANT_6_V4 : FILE
{
	meta:
		description = "Sednit / EVILTOSS Implant by APT28"
		author = "US CERT"
		id = "27118ec8-3713-5670-88d2-3ac57c155c0d"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L1277-L1291"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f5388668e148223bc94680ea84e83b0f2896ccf433523d171c8f46d7069f9a4b"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$ASM = {53 5? 5? [6-15] ff d? 8b ?? b? a0 86 01 00 [7-13] ff d? ?b
         [6-10] c0 [0-1] c3}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
