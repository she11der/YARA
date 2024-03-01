import "pe"

rule REVERSINGLABS_Cert_Blocklist_C667Ffe3A5B0A5Ae7Cf3A9E41682E91B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "83a5e5c2-0932-526b-80aa-800b37088bbd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8882-L8900"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "be2cd688f2d7c458ee764bd7a7250e0116328702db5585b444d631f05cdc701b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NAILS UNLIMITED LIMITED" and (pe.signatures[i].serial=="00:c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b" or pe.signatures[i].serial=="c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b") and 1616976000<=pe.signatures[i].not_after)
}
