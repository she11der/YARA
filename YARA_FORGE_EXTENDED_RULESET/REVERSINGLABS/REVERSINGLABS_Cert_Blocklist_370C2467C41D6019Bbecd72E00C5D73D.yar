import "pe"

rule REVERSINGLABS_Cert_Blocklist_370C2467C41D6019Bbecd72E00C5D73D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "18c5d1bb-21b8-5157-a03b-8bcbdc74c0cd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1816-L1832"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2b99522b75ee83d85b30146cb292b5a8a46dc300fb43dd9d39d9ca96c9d32d9b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "UNINFO SISTEMAS LTDA ME" and pe.signatures[i].serial=="37:0c:24:67:c4:1d:60:19:bb:ec:d7:2e:00:c5:d7:3d" and 1445299199<=pe.signatures[i].not_after)
}
