import "pe"

rule REVERSINGLABS_Cert_Blocklist_Fd41E6Bd7428D3008C8A05F68C9Ac6F2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ef59a76a-3b59-55a2-9da5-c3ba844bbe77"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5500-L5518"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e387664dc9aa746e127b4efb2ef43675f8fb6df66e99d33ef765e8fa306a4f18"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OM-FAS d.o.o." and (pe.signatures[i].serial=="00:fd:41:e6:bd:74:28:d3:00:8c:8a:05:f6:8c:9a:c6:f2" or pe.signatures[i].serial=="fd:41:e6:bd:74:28:d3:00:8c:8a:05:f6:8c:9a:c6:f2") and 1575590400<=pe.signatures[i].not_after)
}
