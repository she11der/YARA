import "pe"

rule REVERSINGLABS_Cert_Blocklist_6Eb40Ea11Eaac847B050De9B59E25Bdc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e9f94ae9-0158-5789-b4d2-88f750442274"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L693-L709"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d0e7ab78fb42c9a8f19cba8e6a8b15d584651a23f1088e1f311589d46145e963"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "My Free Internet Update" and pe.signatures[i].serial=="6e:b4:0e:a1:1e:aa:c8:47:b0:50:de:9b:59:e2:5b:dc" and 1062201599<=pe.signatures[i].not_after)
}
