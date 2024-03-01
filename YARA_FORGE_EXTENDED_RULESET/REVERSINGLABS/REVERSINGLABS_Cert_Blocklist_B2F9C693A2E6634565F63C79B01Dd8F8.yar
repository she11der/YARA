import "pe"

rule REVERSINGLABS_Cert_Blocklist_B2F9C693A2E6634565F63C79B01Dd8F8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c094666a-0bb3-5cb6-82a8-3074b9eed32b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11992-L12010"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f5ec67c082be21a2495ef90fd0a6d4fc4b1379c4903dcc051d39cf1913d5cf20"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PHL E STATE ApS" and (pe.signatures[i].serial=="00:b2:f9:c6:93:a2:e6:63:45:65:f6:3c:79:b0:1d:d8:f8" or pe.signatures[i].serial=="b2:f9:c6:93:a2:e6:63:45:65:f6:3c:79:b0:1d:d8:f8") and 1620000000<=pe.signatures[i].not_after)
}
