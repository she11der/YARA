import "pe"

rule REVERSINGLABS_Cert_Blocklist_83F68Fc6834Bf8Bd2C801A2D1F1Acc76 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "763d4faf-19af-5349-a643-4773055df47a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2690-L2708"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "35552242f9f0a56b45e30e6f376877446f33e24690ff5d7b03dc776fab178afd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Helpful Technologies, Inc" and (pe.signatures[i].serial=="00:83:f6:8f:c6:83:4b:f8:bd:2c:80:1a:2d:1f:1a:cc:76" or pe.signatures[i].serial=="83:f6:8f:c6:83:4b:f8:bd:2c:80:1a:2d:1f:1a:cc:76") and 1407715199<=pe.signatures[i].not_after)
}
