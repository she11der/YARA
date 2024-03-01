import "pe"

rule REVERSINGLABS_Cert_Blocklist_0A1Dc99E4D5264C45A5090F93242A30A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9b85ed8d-ddda-51d0-bfac-5cdc6e4fd94f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5788-L5804"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1985c9c4f4a93c3088eaec3031df93cf87a9d7ee36b94322330caf3c21982f3c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "K & D KOMPANI d.o.o." and pe.signatures[i].serial=="0a:1d:c9:9e:4d:52:64:c4:5a:50:90:f9:32:42:a3:0a" and 1600905601<=pe.signatures[i].not_after)
}
