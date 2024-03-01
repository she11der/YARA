import "pe"

rule REVERSINGLABS_Cert_Blocklist_57D6Dff1Ef96F01B9430666B2733Cc87 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c20b81a1-7331-57a9-9daf-007ec516a473"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2542-L2558"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "40d22137e9c5345859c5f000166da2a3117bcfcc19b4c5e81083cad80dfa6ee4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Smart Plugin Ltda" and pe.signatures[i].serial=="57:d6:df:f1:ef:96:f0:1b:94:30:66:6b:27:33:cc:87" and 1314575999<=pe.signatures[i].not_after)
}
