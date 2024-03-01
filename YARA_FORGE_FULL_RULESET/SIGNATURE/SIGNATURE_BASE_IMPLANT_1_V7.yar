import "pe"

rule SIGNATURE_BASE_IMPLANT_1_V7 : FILE
{
	meta:
		description = "Downrage Implant by APT28"
		author = "US CERT"
		id = "2a28273f-d9a1-5e80-bef1-b488eb0326bd"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L112-L124"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ff8443460e1818fd63e4dcf678bb592940b32978a70ab1633ebaa61c590d3916"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$XOR_FUNCT = { C7 45 ?? ?? ?? 00 10 8B 0E 6A ?? FF 75 ?? E8 ?? ?? FF FF }

	condition:
		( uint16(0)==0x5A4D) and all of them
}
