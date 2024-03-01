import "pe"

rule REVERSINGLABS_Cert_Blocklist_4B093Cb60D4B992266F550934A4Ac7D0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c459c3ac-205c-5c13-959d-c6b40f81222f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13368-L13384"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4b634bc706638d72f2d036d41cf092cac538e930d7d407eebc225b482fd64f51"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LCB SISTEMAS LTDA ME" and pe.signatures[i].serial=="4b:09:3c:b6:0d:4b:99:22:66:f5:50:93:4a:4a:c7:d0" and 1478649600<=pe.signatures[i].not_after)
}
