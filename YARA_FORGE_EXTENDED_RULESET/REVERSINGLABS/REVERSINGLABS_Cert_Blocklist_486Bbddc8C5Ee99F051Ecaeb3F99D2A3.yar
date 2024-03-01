import "pe"

rule REVERSINGLABS_Cert_Blocklist_486Bbddc8C5Ee99F051Ecaeb3F99D2A3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "07b43dd7-e8f1-5b14-a0f4-42294b5b597e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17016-L17032"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "75855e26ba4e01b56a551a006e789c6032cfb02c6f6125a9bdf8becb848db5b2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="48:6b:bd:dc:8c:5e:e9:9f:05:1e:ca:eb:3f:99:d2:a3" and 1473292800<=pe.signatures[i].not_after)
}
