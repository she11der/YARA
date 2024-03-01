import "pe"

rule REVERSINGLABS_Cert_Blocklist_187D92861076E469B5B7A19E2A9Fd4Ba : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0a156a49-c737-5bdb-9178-34121af490d6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14422-L14438"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7383a7fb31a0a913dff1740015ff702642fbb41d8e5a528a8684c80e66026e9d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="18:7d:92:86:10:76:e4:69:b5:b7:a1:9e:2a:9f:d4:ba" and 1476748800<=pe.signatures[i].not_after)
}
