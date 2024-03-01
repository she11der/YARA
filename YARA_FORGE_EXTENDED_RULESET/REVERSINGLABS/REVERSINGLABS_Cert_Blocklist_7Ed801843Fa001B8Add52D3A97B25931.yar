import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Ed801843Fa001B8Add52D3A97B25931 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7c685bb7-3201-5ffc-856b-657d824595ab"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7202-L7218"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b7c9424520afe16bd4769e1be84163ac37b8fb37433931f2e362d90cacc01093"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AM El-Teknik ApS" and pe.signatures[i].serial=="7e:d8:01:84:3f:a0:01:b8:ad:d5:2d:3a:97:b2:59:31" and 1614297600<=pe.signatures[i].not_after)
}
