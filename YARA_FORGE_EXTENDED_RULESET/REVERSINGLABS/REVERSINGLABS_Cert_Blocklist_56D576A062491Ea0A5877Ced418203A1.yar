import "pe"

rule REVERSINGLABS_Cert_Blocklist_56D576A062491Ea0A5877Ced418203A1 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3db67353-6310-54ad-b46a-97daf63fee42"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4556-L4572"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "19bd6834b432f3dc8786b449241082b359275559a112a8ef4a51efe185b256dc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Silvo LLC" and pe.signatures[i].serial=="56:d5:76:a0:62:49:1e:a0:a5:87:7c:ed:41:82:03:a1" and 1596249885<=pe.signatures[i].not_after)
}
