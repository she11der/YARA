import "pe"

rule REVERSINGLABS_Cert_Blocklist_09C89De6F64A7Fdf657E69353C5Fdd44 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f86eafb5-ec59-58c5-b5f9-01a6704fb555"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5176-L5192"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1cb57cd68cda91754307d2e4d94ea011975bbfff0f15134081a5aa11870b0db1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EXON RENTAL SP Z O O" and pe.signatures[i].serial=="09:c8:9d:e6:f6:4a:7f:df:65:7e:69:35:3c:5f:dd:44" and 1601337601<=pe.signatures[i].not_after)
}
