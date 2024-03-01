import "pe"

rule REVERSINGLABS_Cert_Blocklist_5C88313Bd98Bde99C9B9Ac1408A63249 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5108fa8f-3fe6-518c-9bae-b1c44a0ec7a8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13856-L13872"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f958e46e00bf4ab8ecf071502bcda63a84265029bc9c72cea1eaaf72e9003a84"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="5c:88:31:3b:d9:8b:de:99:c9:b9:ac:14:08:a6:32:49" and 1474243200<=pe.signatures[i].not_after)
}
