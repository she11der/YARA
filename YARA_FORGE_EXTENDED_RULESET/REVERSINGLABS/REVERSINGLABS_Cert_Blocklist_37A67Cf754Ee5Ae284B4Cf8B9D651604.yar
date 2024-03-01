import "pe"

rule REVERSINGLABS_Cert_Blocklist_37A67Cf754Ee5Ae284B4Cf8B9D651604 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e85434e1-1ef5-5660-8ba6-b35cbbe7510d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9058-L9074"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "22cb71eebbb212a4436847c11c7ca9cefaf118086b024014c12498a6a5953af5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORTH PROPERTY LTD" and pe.signatures[i].serial=="37:a6:7c:f7:54:ee:5a:e2:84:b4:cf:8b:9d:65:16:04" and 1617321600<=pe.signatures[i].not_after)
}
