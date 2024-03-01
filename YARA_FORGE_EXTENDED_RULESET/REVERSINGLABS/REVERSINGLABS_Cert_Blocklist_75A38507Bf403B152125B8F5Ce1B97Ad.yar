import "pe"

rule REVERSINGLABS_Cert_Blocklist_75A38507Bf403B152125B8F5Ce1B97Ad : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing Zeus malware."
		author = "ReversingLabs"
		id = "6805abd8-217e-5179-ab5a-297e2a17e65e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L171-L187"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "af21cee3ee92268c3aa0106a245e5a00c5ba892fca3e4fd2dc55e302ed5d470a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "isonet ag" and pe.signatures[i].serial=="75:a3:85:07:bf:40:3b:15:21:25:b8:f5:ce:1b:97:ad" and 1395359999<=pe.signatures[i].not_after)
}
