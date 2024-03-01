import "pe"

rule REVERSINGLABS_Cert_Blocklist_462Baada57570F70Df76D10B9E7Bf2B7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2863a050-ebce-5322-b64a-9160adf6cc21"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13948-L13964"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c48207907339ce3fb7b6bc630097761a24495a9d4e69d421f2bdb36ddc92abcb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DVERI FADO, TOV" and pe.signatures[i].serial=="46:2b:aa:da:57:57:0f:70:df:76:d1:0b:9e:7b:f2:b7" and 1551744000<=pe.signatures[i].not_after)
}
