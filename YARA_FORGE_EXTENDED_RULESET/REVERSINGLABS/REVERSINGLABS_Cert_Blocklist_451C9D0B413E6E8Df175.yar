import "pe"

rule REVERSINGLABS_Cert_Blocklist_451C9D0B413E6E8Df175 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "adc832c0-166d-52d1-aeec-2fc92ff52d02"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1960-L1976"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7c94d87f79c9add4d7bf2a63d0774449319aa56cbc631dd9b0f19ed9bb9837d4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PRASAD UPENDRA" and pe.signatures[i].serial=="45:1c:9d:0b:41:3e:6e:8d:f1:75" and 1442275199<=pe.signatures[i].not_after)
}
