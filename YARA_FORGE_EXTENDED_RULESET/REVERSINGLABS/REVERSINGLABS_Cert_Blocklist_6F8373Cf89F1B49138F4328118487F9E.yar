import "pe"

rule REVERSINGLABS_Cert_Blocklist_6F8373Cf89F1B49138F4328118487F9E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "80c5d205-7f5e-5e06-b490-f33205154974"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4986-L5002"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f926c2f73d47d463721a0cad48d9866192df55d71867941a40cba7e0b7725102"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "30 PTY LTD" and pe.signatures[i].serial=="6f:83:73:cf:89:f1:b4:91:38:f4:32:81:18:48:7f:9e" and 1572566400<=pe.signatures[i].not_after)
}
