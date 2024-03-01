import "pe"

rule REVERSINGLABS_Cert_Blocklist_5B1C3F7Bbaa91Ca49B06A5C1004Ee5Be : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b78e7f2b-8122-5df6-ad79-393db9e0498d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17106-L17122"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9a8d9acc87668a6fbd9fdd52b6ef69d18de8f19d8f3d3ca8eeb630c6e8c25c65"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jin Yuguang" and pe.signatures[i].serial=="5b:1c:3f:7b:ba:a9:1c:a4:9b:06:a5:c1:00:4e:e5:be" and 1440643213<=pe.signatures[i].not_after)
}
