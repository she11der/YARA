import "pe"

rule REVERSINGLABS_Cert_Blocklist_0B980Fc8783E4F158E41829Ab21Bab81 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f7358f71-421f-57fa-abdf-ab479f4b7007"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9456-L9472"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b0f43caec1cfc5b2d1512d7fcf0bcf1e02fc81764b4376b081f38c4de328eab2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Idris Kanchwala Holding Corp." and pe.signatures[i].serial=="0b:98:0f:c8:78:3e:4f:15:8e:41:82:9a:b2:1b:ab:81" and 1631750400<=pe.signatures[i].not_after)
}
