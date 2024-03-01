import "pe"

rule REVERSINGLABS_Cert_Blocklist_B06Bc166Fc765Dacd2F7448C8Cdd9205 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4b27c958-58f1-5fbd-8a39-aedfe4dafe39"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12178-L12196"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2c47166f02c7f94bb4f82296e3220ff7ca3c6c53566d855b2fe77cb842a5fb43"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GAS Avto, d.o.o." and (pe.signatures[i].serial=="00:b0:6b:c1:66:fc:76:5d:ac:d2:f7:44:8c:8c:dd:92:05" or pe.signatures[i].serial=="b0:6b:c1:66:fc:76:5d:ac:d2:f7:44:8c:8c:dd:92:05") and 1615507200<=pe.signatures[i].not_after)
}
