import "pe"

rule REVERSINGLABS_Cert_Blocklist_3Fd3661533Eef209153C9Afec3Ba4D8A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e45d66b0-58ae-5054-b0a7-47a001daac7a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7260-L7276"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ce6c07b8ae54db03e4fa2739856a8d3dc2051c051a10c3c73501dad4296dde97"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SFB Regnskabsservice ApS" and pe.signatures[i].serial=="3f:d3:66:15:33:ee:f2:09:15:3c:9a:fe:c3:ba:4d:8a" and 1614816000<=pe.signatures[i].not_after)
}
