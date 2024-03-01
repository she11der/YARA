import "pe"

rule REVERSINGLABS_Cert_Blocklist_1F84E030A0Ed10D5Ffe2B81B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "170dae5a-ed7e-5f20-9ccd-94724e4b2084"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17142-L17158"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "097655cb2965ae71efb905ddf20ed30c240d25e03d08a1b6c87b472533ccc9d8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="1f:84:e0:30:a0:ed:10:d5:ff:e2:b8:1b" and 1476869735<=pe.signatures[i].not_after)
}
