import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Aec3D3F752A38617C1D7A677D0B5591 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "02f2bf36-e573-502c-8ecc-843a6e627c2b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8300-L8316"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b299833a19944ca6943ba9c974ec95369c57cd61acc8b2e1b5310edd077762c2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SILVER d.o.o." and pe.signatures[i].serial=="1a:ec:3d:3f:75:2a:38:61:7c:1d:7a:67:7d:0b:55:91" and 1611705600<=pe.signatures[i].not_after)
}
