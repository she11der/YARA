import "pe"

rule REVERSINGLABS_Cert_Blocklist_E6C05C5A2222Bf92818324A3A7374Ad3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2b5b79d8-e8fa-5593-b4c4-89af1f711152"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9728-L9746"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bea8fea49144abc109e33a5964bb8e113aa61b4cd70c72a43183cb0840429571"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ANAQA EVENTS LTD" and (pe.signatures[i].serial=="00:e6:c0:5c:5a:22:22:bf:92:81:83:24:a3:a7:37:4a:d3" or pe.signatures[i].serial=="e6:c0:5c:5a:22:22:bf:92:81:83:24:a3:a7:37:4a:d3") and 1634720407<=pe.signatures[i].not_after)
}
