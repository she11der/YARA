import "pe"

rule REVERSINGLABS_Cert_Blocklist_3E1656Dfcaacfed7C2D2564355698Aa3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "57b75eaa-2cb2-5713-8eb3-065f90a1fdd5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2862-L2878"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ba7cca8d71f571644cabd3d491cddefffd05ca7a838f262a343a01e4a09bb72a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "John W.Richard" and pe.signatures[i].serial=="3e:16:56:df:ca:ac:fe:d7:c2:d2:56:43:55:69:8a:a3" and 1385251199<=pe.signatures[i].not_after)
}
