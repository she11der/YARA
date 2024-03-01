import "pe"

rule REVERSINGLABS_Cert_Blocklist_55Efe24B9674855Baf16E67716479C71 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c1a4102e-ce78-5a4d-95ea-b9e394df0c28"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L423-L439"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2cf7a76ae3c3a698564013ff545c74d0319face5aa19416c93bf10f45f84f8c9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "S2BVISIO BELGIQUE SA" and pe.signatures[i].serial=="55:ef:e2:4b:96:74:85:5b:af:16:e6:77:16:47:9c:71" and 1374451199<=pe.signatures[i].not_after)
}
