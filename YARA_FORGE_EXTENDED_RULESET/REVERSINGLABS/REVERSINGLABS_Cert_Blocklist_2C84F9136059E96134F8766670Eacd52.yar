import "pe"

rule REVERSINGLABS_Cert_Blocklist_2C84F9136059E96134F8766670Eacd52 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "af7eb5ff-570f-5886-b550-3d327d05fabe"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13312-L13328"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d6778630dcc3e4fe2816e6dee1b823e616f53de8a924057495c7c252948a71b4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Open Source Developer, DIEGO MANUEL RODRIGUEZ" and pe.signatures[i].serial=="2c:84:f9:13:60:59:e9:61:34:f8:76:66:70:ea:cd:52" and 1442215311<=pe.signatures[i].not_after)
}
