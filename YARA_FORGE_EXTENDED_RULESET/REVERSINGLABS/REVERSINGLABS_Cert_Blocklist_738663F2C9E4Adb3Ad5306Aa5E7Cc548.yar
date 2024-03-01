import "pe"

rule REVERSINGLABS_Cert_Blocklist_738663F2C9E4Adb3Ad5306Aa5E7Cc548 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9fa41321-9736-5e67-b561-005b6d893e3f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16618-L16634"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "518a22e31432ee42e6aceb861815f7f9e84f2430b7fb3a78b498e45c584584ab"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GIN-Konsalt" and pe.signatures[i].serial=="73:86:63:f2:c9:e4:ad:b3:ad:53:06:aa:5e:7c:c5:48" and 1498435200<=pe.signatures[i].not_after)
}
