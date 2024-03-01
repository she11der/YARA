import "pe"

rule REVERSINGLABS_Cert_Blocklist_169138A86954Be1D9B264F47 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "56653f72-39af-50e7-9908-e516f9b21084"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16926-L16942"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1584e39b4e2025611bcb7bbbd92b97d25d12ddbb1e5c282db87730a03f7f56b1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="16:91:38:a8:69:54:be:1d:9b:26:4f:47" and 1477636474<=pe.signatures[i].not_after)
}
