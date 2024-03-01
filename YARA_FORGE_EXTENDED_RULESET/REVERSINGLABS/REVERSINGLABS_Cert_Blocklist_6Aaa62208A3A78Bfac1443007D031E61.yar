import "pe"

rule REVERSINGLABS_Cert_Blocklist_6Aaa62208A3A78Bfac1443007D031E61 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dd6dca76-ff5b-51a8-9318-20a88eb44ffb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9258-L9274"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7ba7f69514230fe636efc0a12fb9ac489a5a80ca1f5bcdb050dd30ee8f69659c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Solar LLC" and pe.signatures[i].serial=="6a:aa:62:20:8a:3a:78:bf:ac:14:43:00:7d:03:1e:61" and 1608163200<=pe.signatures[i].not_after)
}
