import "pe"

rule REVERSINGLABS_Cert_Blocklist_06A164Ec5978497741Ee6Cec9966871B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6c73206d-3d5c-5540-a2e1-d00138d7e1b5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L333-L349"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8a27015d94a3bd8543a8ca9202831ffc9c9e65f61bf26ed6825c3e746b6af0d4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JOHN WILLIAM RICHARD" and pe.signatures[i].serial=="06:a1:64:ec:59:78:49:77:41:ee:6c:ec:99:66:87:1b" and 1385596799<=pe.signatures[i].not_after)
}
