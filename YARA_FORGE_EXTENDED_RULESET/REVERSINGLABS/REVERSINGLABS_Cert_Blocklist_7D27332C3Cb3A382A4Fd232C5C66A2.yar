import "pe"

rule REVERSINGLABS_Cert_Blocklist_7D27332C3Cb3A382A4Fd232C5C66A2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d8390528-ff27-514d-ab89-fd563a19ce3c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11028-L11044"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c1c50015db7f97b530819b40e2578463a6021bfff8e2582858a4c3fbd1a9b9bc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MALVINA RECRUITMENT LIMITED" and pe.signatures[i].serial=="7d:27:33:2c:3c:b3:a3:82:a4:fd:23:2c:5c:66:a2" and 1655424000<=pe.signatures[i].not_after)
}
