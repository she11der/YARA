import "pe"

rule REVERSINGLABS_Cert_Blocklist_0B0D17Ec1449B4B2D38Fcb0F20Fbcd3A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4484b00d-8fad-5f8f-9030-67216f2820a3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2338-L2354"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3121f2c49d0d4c396023924521f2c980045b6f07d082e49447429e9cd640e0ef"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WEBPIC DESENVOLVIMENTO DE SOFTWARE LTDA" and pe.signatures[i].serial=="0b:0d:17:ec:14:49:b4:b2:d3:8f:cb:0f:20:fb:cd:3a" and 1394150399<=pe.signatures[i].not_after)
}
