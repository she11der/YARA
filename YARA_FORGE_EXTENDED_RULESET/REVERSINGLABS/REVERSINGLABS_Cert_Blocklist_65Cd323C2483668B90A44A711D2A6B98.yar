import "pe"

rule REVERSINGLABS_Cert_Blocklist_65Cd323C2483668B90A44A711D2A6B98 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e2ed910d-2264-58c1-a1a0-3c131020a2cf"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8530-L8546"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "653aff6f3913f1bf51e90e7a835dbb5441457175797cefdddd234a6c2c0f11ad"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Giperion" and pe.signatures[i].serial=="65:cd:32:3c:24:83:66:8b:90:a4:4a:71:1d:2a:6b:98" and 1602547200<=pe.signatures[i].not_after)
}
