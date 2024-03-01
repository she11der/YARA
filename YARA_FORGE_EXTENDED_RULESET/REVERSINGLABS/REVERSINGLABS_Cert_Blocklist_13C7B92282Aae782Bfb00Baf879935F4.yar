import "pe"

rule REVERSINGLABS_Cert_Blocklist_13C7B92282Aae782Bfb00Baf879935F4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "cc147c06-e0cf-5536-be3c-17e838b346a9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5636-L5652"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d4edbb446a51e5153ba88d6757d5fb610303eac3fd4bdd3b987b508dc618d2dc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and pe.signatures[i].serial=="13:c7:b9:22:82:aa:e7:82:bf:b0:0b:af:87:99:35:f4" and 1603130510<=pe.signatures[i].not_after)
}
