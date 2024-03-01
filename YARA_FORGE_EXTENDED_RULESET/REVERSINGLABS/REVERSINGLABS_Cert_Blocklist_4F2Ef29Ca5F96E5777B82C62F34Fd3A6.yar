import "pe"

rule REVERSINGLABS_Cert_Blocklist_4F2Ef29Ca5F96E5777B82C62F34Fd3A6 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "6cfb6ae0-8eba-503b-8bb7-ac72746d9aa2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L63-L79"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e8f27c4a72f416a16acabb1de606fdde7dc694256809fdb952a25313dda0d34e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bit9, Inc" and pe.signatures[i].serial=="4f:2e:f2:9c:a5:f9:6e:57:77:b8:2c:62:f3:4f:d3:a6" and 1342051200<=pe.signatures[i].not_after)
}
