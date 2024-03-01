import "pe"

rule REVERSINGLABS_Cert_Blocklist_044E05Bb1A01A1Cbb50Cfb6Cd24E5D6B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c0796bc3-96cd-5d12-a0ee-97d8ed4a3076"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6310-L6326"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "40c80d3b6bedb0b3454e14501745a6e82b6ea9ac202748867a2e937fb79c6f6c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MUSTER PLUS SP Z O O" and pe.signatures[i].serial=="04:4e:05:bb:1a:01:a1:cb:b5:0c:fb:6c:d2:4e:5d:6b" and 1601427600<=pe.signatures[i].not_after)
}
