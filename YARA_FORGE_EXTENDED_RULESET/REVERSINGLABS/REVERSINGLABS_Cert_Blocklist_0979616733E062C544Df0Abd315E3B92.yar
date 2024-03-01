import "pe"

rule REVERSINGLABS_Cert_Blocklist_0979616733E062C544Df0Abd315E3B92 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "73222a8d-df63-5784-b5a2-0d936db8ddcb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1180-L1196"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "034b233d6b6dd82ad9fa1ec99db1effa3daaa5bb478d448133c479ac728117ad"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jessica Karam" and pe.signatures[i].serial=="09:79:61:67:33:e0:62:c5:44:df:0a:bd:31:5e:3b:92" and 1408319999<=pe.signatures[i].not_after)
}
