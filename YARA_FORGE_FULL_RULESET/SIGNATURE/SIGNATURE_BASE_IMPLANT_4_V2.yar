import "pe"

rule SIGNATURE_BASE_IMPLANT_4_V2 : FILE
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		id = "2edaeb08-19bc-5ab4-bc75-40c16ba85d9f"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L505-L520"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "dd4edd238cdc3d376c1d5bcea6c8df57f4ef03369c0ca22107241812e0a1bb94"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$BUILD_USER32 = {75 73 65 72 ?? ?? ?? 33 32 2E 64}
		$BUILD_ADVAPI32 = {61 64 76 61 ?? ?? ?? 70 69 33 32}
		$CONSTANT = {26 80 AC C8}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
