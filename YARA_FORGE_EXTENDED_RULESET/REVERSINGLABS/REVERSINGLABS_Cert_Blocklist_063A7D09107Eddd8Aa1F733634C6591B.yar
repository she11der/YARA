import "pe"

rule REVERSINGLABS_Cert_Blocklist_063A7D09107Eddd8Aa1F733634C6591B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0169cf47-72b0-53ec-bc8f-c2a80febad3a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6406-L6422"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "19f11e1d9ce95eb4bc75387a0118c230388a13cd07b02e00ea1d65cdcc0b2bd7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Smart Line Logistics" and pe.signatures[i].serial=="06:3a:7d:09:10:7e:dd:d8:aa:1f:73:36:34:c6:59:1b" and 1605712706<=pe.signatures[i].not_after)
}
