import "pe"

rule REVERSINGLABS_Cert_Blocklist_4A2E337Fff23E5B2A1321Ffde56D1759 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e5cae614-eff1-5c3d-a7f6-c41b0a2c412e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11104-L11120"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bc2df95ddf1ef3d5f83d14852e1cf6cbf4b71bfbe88fc97c2a4553e8581ddf47"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Karolina Klimowska" and pe.signatures[i].serial=="4a:2e:33:7f:ff:23:e5:b2:a1:32:1f:fd:e5:6d:17:59" and 1660314070<=pe.signatures[i].not_after)
}
