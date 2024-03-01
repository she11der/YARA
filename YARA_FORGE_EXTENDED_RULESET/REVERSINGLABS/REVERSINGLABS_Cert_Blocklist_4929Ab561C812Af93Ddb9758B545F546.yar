import "pe"

rule REVERSINGLABS_Cert_Blocklist_4929Ab561C812Af93Ddb9758B545F546 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6e8ffb39-d00d-54ca-a4be-68f6dd92d798"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12294-L12310"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "12235e324b92b83e9cfaed7cbcff5d093b8b1d7528dd5ac327159cde6e9a4d1f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Everything Wow s.r.o." and pe.signatures[i].serial=="49:29:ab:56:1c:81:2a:f9:3d:db:97:58:b5:45:f5:46" and 1594252800<=pe.signatures[i].not_after)
}
