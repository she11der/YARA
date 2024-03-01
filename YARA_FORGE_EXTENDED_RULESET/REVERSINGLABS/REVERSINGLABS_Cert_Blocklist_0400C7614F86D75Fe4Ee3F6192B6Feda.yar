import "pe"

rule REVERSINGLABS_Cert_Blocklist_0400C7614F86D75Fe4Ee3F6192B6Feda : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "500c9604-cc07-52b1-8c46-09894d132205"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12140-L12156"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "47735267e9a0fb8107f6c4008bacc8aada1705f6714a0447dacc3928fc20cad6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "StackUp ApS" and pe.signatures[i].serial=="04:00:c7:61:4f:86:d7:5f:e4:ee:3f:61:92:b6:fe:da" and 1626393601<=pe.signatures[i].not_after)
}
