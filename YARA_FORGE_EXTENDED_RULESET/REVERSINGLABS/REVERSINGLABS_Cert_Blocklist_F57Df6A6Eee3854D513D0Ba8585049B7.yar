import "pe"

rule REVERSINGLABS_Cert_Blocklist_F57Df6A6Eee3854D513D0Ba8585049B7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b31f73d5-ff9e-5be7-b806-8838ddb5d29d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13892-L13910"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "09d5998960fb65eda56cd698c5ff50d87ba7a811cbb128bc7485c0f124e14cba"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "smnetworks" and (pe.signatures[i].serial=="00:f5:7d:f6:a6:ee:e3:85:4d:51:3d:0b:a8:58:50:49:b7" or pe.signatures[i].serial=="f5:7d:f6:a6:ee:e3:85:4d:51:3d:0b:a8:58:50:49:b7") and 1277769600<=pe.signatures[i].not_after)
}
