import "pe"

rule REVERSINGLABS_Cert_Blocklist_6889Aab6202Bcc5F11Caedf4D04F435B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d4499a1d-aa8d-5056-ad91-439f27f00c33"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12894-L12910"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b2261ed8001929be8f80f73cc0c5076138f4794c73cbffd63773da5fc44639a8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "C4DL Media" and pe.signatures[i].serial=="68:89:aa:b6:20:2b:cc:5f:11:ca:ed:f4:d0:4f:43:5b" and 1231891200<=pe.signatures[i].not_after)
}
