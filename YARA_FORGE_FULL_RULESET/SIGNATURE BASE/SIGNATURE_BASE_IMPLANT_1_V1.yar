import "pe"

rule SIGNATURE_BASE_IMPLANT_1_V1 : FILE
{
	meta:
		description = "Downrage Implant by APT28"
		author = "US CERT"
		id = "eb3fc39b-08ca-51df-a9b4-7b28b107b700"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L12-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4df04daf70da482877874c530a3ad76fddebec2946931b60f98aa6c4e31f21ae"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = {6A ?? E8 ?? ?? FF FF 59 85 C0 74 0B 8B C8 E8 ?? ?? FF FF 8B F0
         EB 02 33 F6 8B CE E8 ?? ?? FF FF 85 F6 74 0E 8B CE E8 ?? ?? FF FF 56
         E8 ?? ?? FF FF 59}

	condition:
		( uint16(0)==0x5A4D) and all of them
}
