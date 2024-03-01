import "pe"

rule SIGNATURE_BASE_IMPLANT_2_V17 : FILE
{
	meta:
		description = "CORESHELL/SOURFACE Implant by APT28"
		author = "US CERT"
		id = "dc3a6b08-1ac4-5fa2-a710-657514d45606"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L331-L347"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ea2793e6ce9e9d97e70a9452a38eb4d5ddbcc275af6ae7f5d094dc77e112d278"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = { 24108b44241c894424148b4424246836 }
		$STR2 = { 518d4ddc516a018bd08b4de4e8360400 }
		$STR3 = { e48178061591df75740433f6eb1a8b48 }
		$STR4 = { 33d2f775f88b45d402d903c641321c3a }
		$STR5 = { 006a0056ffd083f8ff74646a008d45f8 }

	condition:
		( uint16(0)==0x5A4D) and 2 of them
}
