import "pe"

rule REVERSINGLABS_Cert_Blocklist_D2Caf7908Aaebfa1A8F3E2136Fece024 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6c2c4fc6-5359-55fa-bf79-9202caa5f326"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4498-L4516"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cf4d17274ef36d61e78578d34634bf6e5fb0fb857a9a92184916b0f3b8484568"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FANATOR, OOO" and (pe.signatures[i].serial=="00:d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24" or pe.signatures[i].serial=="d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24") and 1599041760<=pe.signatures[i].not_after)
}
