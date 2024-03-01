import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Be35D025E65Cc7A4Ee01F72 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "533bcad1-b589-5a05-8f35-32fcb79c7f68"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4308-L4324"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "dad7ab834a67d36c0b63e45922aea566dc0aaf922be2b74161616b3caea83fdc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Logika OOO" and pe.signatures[i].serial=="7b:e3:5d:02:5e:65:cc:7a:4e:e0:1f:72" and 1594976445<=pe.signatures[i].not_after)
}
