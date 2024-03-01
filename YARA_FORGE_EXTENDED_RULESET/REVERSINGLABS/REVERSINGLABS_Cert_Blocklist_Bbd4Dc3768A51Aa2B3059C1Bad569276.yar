import "pe"

rule REVERSINGLABS_Cert_Blocklist_Bbd4Dc3768A51Aa2B3059C1Bad569276 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ee861c79-fea2-5931-873d-b76e5bdef593"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8338-L8356"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f336570834e0663c6e589fa22b3541f4f79c40ff945dd91f1fd1258a96adeceb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JJ ELECTRICAL SERVICES LIMITED" and (pe.signatures[i].serial=="00:bb:d4:dc:37:68:a5:1a:a2:b3:05:9c:1b:ad:56:92:76" or pe.signatures[i].serial=="bb:d4:dc:37:68:a5:1a:a2:b3:05:9c:1b:ad:56:92:76") and 1607472000<=pe.signatures[i].not_after)
}
