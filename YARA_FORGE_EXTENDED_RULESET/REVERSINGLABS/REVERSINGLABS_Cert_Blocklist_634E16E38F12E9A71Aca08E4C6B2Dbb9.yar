import "pe"

rule REVERSINGLABS_Cert_Blocklist_634E16E38F12E9A71Aca08E4C6B2Dbb9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4aa7bea7-06fb-5d90-bac4-c8ca1ca5c02f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8602-L8618"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "08950f276e5cf3fe4b5f7421ba671dfd72585aac3bbed7868fdb0e5aa90ec10e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AUTO RESPONSE LTD CYF" and pe.signatures[i].serial=="63:4e:16:e3:8f:12:e9:a7:1a:ca:08:e4:c6:b2:db:b9" and 1616112000<=pe.signatures[i].not_after)
}
