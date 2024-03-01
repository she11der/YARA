import "pe"

rule REVERSINGLABS_Cert_Blocklist_D3356318924C8C42959Bf1D1574E6482 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "36b12300-6535-5644-9145-9f532b49a421"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7560-L7578"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a672054a776d0715fc888578bcb559d24ef54b4c523f7d49a39ded2586c3140a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ADV TOURS d.o.o." and (pe.signatures[i].serial=="00:d3:35:63:18:92:4c:8c:42:95:9b:f1:d1:57:4e:64:82" or pe.signatures[i].serial=="d3:35:63:18:92:4c:8c:42:95:9b:f1:d1:57:4e:64:82") and 1613001600<=pe.signatures[i].not_after)
}
