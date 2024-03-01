import "pe"

rule SIGNATURE_BASE_IMPLANT_7_V1 : FILE
{
	meta:
		description = "Implant 7 by APT29"
		author = "US CERT"
		id = "ce83c157-af03-55cb-a2be-0b6543fedb5b"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L1368-L1381"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "996f81fe006e0ab15adab46275fdb60251e6c6616da33df600fadfc2684c24af"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = { 8A 44 0A 03 32 C3 0F B6 C0 66 89 04 4E 41 3B CF 72 EE }
		$STR2 = { F3 0F 6F 04 08 66 0F EF C1 F3 0F 7F 04 11 83 C1 10 3B CF 72 EB }

	condition:
		( uint16(0)==0x5A4D) and ($STR1 or $STR2)
}
