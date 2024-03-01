import "pe"

rule REVERSINGLABS_Cert_Blocklist_5F273626859Ae4Bc4Becbbeb71E2Ab2D : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "a80dcaba-73f9-51d0-a75a-b6348fd305c6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1380-L1396"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c8be504f075041508f299b1df03d9cb9e58d9a89f49b7a926676033d18b108ba"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Adobe Systems" and pe.signatures[i].serial=="5f:27:36:26:85:9a:e4:bc:4b:ec:bb:eb:71:e2:ab:2d" and 1341792000<=pe.signatures[i].not_after)
}
