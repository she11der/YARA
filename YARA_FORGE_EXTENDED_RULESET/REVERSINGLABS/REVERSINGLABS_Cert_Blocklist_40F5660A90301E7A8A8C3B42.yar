import "pe"

rule REVERSINGLABS_Cert_Blocklist_40F5660A90301E7A8A8C3B42 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c47bb4f0-d60b-5948-ac10-6083606ed46a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12122-L12138"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3573d1d5f11df106f1f6f44f8b0164992f2a50707c6df7b08b05ed9ea7d9173b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Booz Allen Hamilton Inc." and pe.signatures[i].serial=="40:f5:66:0a:90:30:1e:7a:8a:8c:3b:42" and 1641833688<=pe.signatures[i].not_after)
}
