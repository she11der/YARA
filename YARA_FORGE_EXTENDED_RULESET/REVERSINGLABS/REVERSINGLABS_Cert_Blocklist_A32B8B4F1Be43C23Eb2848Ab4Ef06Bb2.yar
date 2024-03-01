import "pe"

rule REVERSINGLABS_Cert_Blocklist_A32B8B4F1Be43C23Eb2848Ab4Ef06Bb2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2ced71bb-622c-5597-91c3-210b9b5f3a4e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11612-L11630"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "dd7d44349baaf4a2e2f61b38cef31f288110bb03944fd4593f52a0ab03b9d172"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pak El AB" and (pe.signatures[i].serial=="00:a3:2b:8b:4f:1b:e4:3c:23:eb:28:48:ab:4e:f0:6b:b2" or pe.signatures[i].serial=="a3:2b:8b:4f:1b:e4:3c:23:eb:28:48:ab:4e:f0:6b:b2") and 1673395200<=pe.signatures[i].not_after)
}
