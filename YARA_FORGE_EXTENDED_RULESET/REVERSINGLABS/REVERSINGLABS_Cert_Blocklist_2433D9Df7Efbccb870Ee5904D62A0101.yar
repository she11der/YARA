import "pe"

rule REVERSINGLABS_Cert_Blocklist_2433D9Df7Efbccb870Ee5904D62A0101 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6cd46771-06ea-51c9-ad84-4b28f4f8442b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13930-L13946"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "92a2effe1b94345f52130e4cb1db181f1990e58eaefb9c74375c14249cc1be22"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Conpavi AG" and pe.signatures[i].serial=="24:33:d9:df:7e:fb:cc:b8:70:ee:59:04:d6:2a:01:01" and 1322438400<=pe.signatures[i].not_after)
}
