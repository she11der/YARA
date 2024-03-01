import "pe"

rule REVERSINGLABS_Cert_Blocklist_51Cd5393514F7Ace2B407C3Dbfb09D8D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ac86893f-2edd-5f1c-96eb-4cb140e8e001"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6864-L6880"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4cd08b9113a7c1f4f2d438ac59ad0be503daded3a08b8c8e8ce3e0dfdddf259e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APPI CZ a.s" and pe.signatures[i].serial=="51:cd:53:93:51:4f:7a:ce:2b:40:7c:3d:bf:b0:9d:8d" and 1605299467<=pe.signatures[i].not_after)
}
