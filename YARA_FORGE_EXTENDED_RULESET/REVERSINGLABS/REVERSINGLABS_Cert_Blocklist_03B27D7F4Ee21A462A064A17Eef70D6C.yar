import "pe"

rule REVERSINGLABS_Cert_Blocklist_03B27D7F4Ee21A462A064A17Eef70D6C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9d32947c-778f-5e2d-b0b1-4a17a108035e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7368-L7384"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b303751e354c346f73368de94b66a960dd12efa0730d2ab14af743810669ac81"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CCL TRADING LIMITED" and pe.signatures[i].serial=="03:b2:7d:7f:4e:e2:1a:46:2a:06:4a:17:ee:f7:0d:6c" and 1613952000<=pe.signatures[i].not_after)
}
