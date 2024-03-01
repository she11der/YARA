import "pe"

rule REVERSINGLABS_Cert_Blocklist_A918455C0D4Da7Ca474F41F11A7Cf38C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "959b10fe-fbd0-5642-a5d9-4ac2e0474666"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9552-L9570"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ea30d85c057f9363ce29d4c024097c50a8752dd2095481181322fe5d5c92bb4b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MIDDRA INTERNATIONAL CORP." and (pe.signatures[i].serial=="00:a9:18:45:5c:0d:4d:a7:ca:47:4f:41:f1:1a:7c:f3:8c" or pe.signatures[i].serial=="a9:18:45:5c:0d:4d:a7:ca:47:4f:41:f1:1a:7c:f3:8c") and 1618963200<=pe.signatures[i].not_after)
}
