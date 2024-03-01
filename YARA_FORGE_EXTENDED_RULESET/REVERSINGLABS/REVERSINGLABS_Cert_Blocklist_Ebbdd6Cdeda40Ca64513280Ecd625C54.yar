import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ebbdd6Cdeda40Ca64513280Ecd625C54 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2cf769dc-5108-5f18-a51e-e152180a2b66"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3120-L3138"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1d419f2fe2a9bf744bdde48adc50e0bc48746f1576f96570385a2a1c9ba92d21"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IT PUT LIMITED" and (pe.signatures[i].serial=="00:eb:bd:d6:cd:ed:a4:0c:a6:45:13:28:0e:cd:62:5c:54" or pe.signatures[i].serial=="eb:bd:d6:cd:ed:a4:0c:a6:45:13:28:0e:cd:62:5c:54") and 1549238400<=pe.signatures[i].not_after)
}
