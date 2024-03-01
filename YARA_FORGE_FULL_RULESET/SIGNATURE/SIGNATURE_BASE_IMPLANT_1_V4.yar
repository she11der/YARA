import "pe"

rule SIGNATURE_BASE_IMPLANT_1_V4 : FILE
{
	meta:
		description = "Downrage Implant by APT28"
		author = "US CERT"
		id = "0362b885-de59-5715-80f2-106e5e91d1fa"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L60-L73"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "eb8e4ed38e2e4d3991543c526c7dc458eec78c517d2c5eaa06a3a3cfb48d770f"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$XOR_LOOP = { 8B 45 FC 8D 0C 06 33 D2 6A 0B 8B C6 5B F7 F3 8A 82 ?? ??
         ?? ?? 32 04 0F 46 88 01 3B 75 0C 7C E0 }

	condition:
		( uint16(0)==0x5A4D) and all of them
}
