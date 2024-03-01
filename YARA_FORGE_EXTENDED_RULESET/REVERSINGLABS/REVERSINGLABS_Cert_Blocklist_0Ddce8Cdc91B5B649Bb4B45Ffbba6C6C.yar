import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Ddce8Cdc91B5B649Bb4B45Ffbba6C6C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9de11ec8-f408-593c-895f-08dff703ff10"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3734-L3750"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "622e6ed08ca26908539519f37cf493f8030100bd5e88cb05e851b7d56b0f4c0d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SLIM DOG GROUP SP Z O O" and pe.signatures[i].serial=="0d:dc:e8:cd:c9:1b:5b:64:9b:b4:b4:5f:fb:ba:6c:6c" and 1580722435<=pe.signatures[i].not_after)
}
