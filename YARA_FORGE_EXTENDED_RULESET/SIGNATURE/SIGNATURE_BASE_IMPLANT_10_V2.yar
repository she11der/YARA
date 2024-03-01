import "pe"

rule SIGNATURE_BASE_IMPLANT_10_V2 : FILE
{
	meta:
		description = "CozyDuke / CozyCar / CozyBear Implant by APT29"
		author = "US CERT"
		id = "9c6d4eb9-98a5-5c6d-ba3a-0ce7524c5d2a"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L1468-L1481"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "dc201d25b1d6cf8f88ae3bee18057902c4d64316aa9debc9248b0d8aa7f6d170"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$xor = { 34 ?? 66 33 C1 48 FF C1 }
		$nop = { 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00}

	condition:
		uint16(0)==0x5A4D and $xor and $nop
}
