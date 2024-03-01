import "pe"

rule REVERSINGLABS_Cert_Blocklist_0492F5C18E26Fa0Cd7E15067674Aff1C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6a176d4a-5d3e-5184-b923-12d561e7034a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1762-L1778"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d47d59d7680000d6c35181be2d9b034c2ecb7ca754a39c8e11750ddd7246b47c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ghada Saffarini" and pe.signatures[i].serial=="04:92:f5:c1:8e:26:fa:0c:d7:e1:50:67:67:4a:ff:1c" and 1445990399<=pe.signatures[i].not_after)
}
