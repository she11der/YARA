import "pe"

rule REVERSINGLABS_Cert_Blocklist_F385E765Acfb95605C9B35Ca4C32F80E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "865f8daf-35c4-5437-9c97-9b9fc48d7d70"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2710-L2728"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c73c8f1913d3423a52f5e77751813460ae9200eb3cb1cc6e2ec30f37f0da8152"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CWI SOFTWARE LTDA" and (pe.signatures[i].serial=="00:f3:85:e7:65:ac:fb:95:60:5c:9b:35:ca:4c:32:f8:0e" or pe.signatures[i].serial=="f3:85:e7:65:ac:fb:95:60:5c:9b:35:ca:4c:32:f8:0e") and 1382313599<=pe.signatures[i].not_after)
}
