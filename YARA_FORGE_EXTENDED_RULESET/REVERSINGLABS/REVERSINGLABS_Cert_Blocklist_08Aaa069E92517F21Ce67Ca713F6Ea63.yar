import "pe"

rule REVERSINGLABS_Cert_Blocklist_08Aaa069E92517F21Ce67Ca713F6Ea63 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d468530e-8a51-583e-a108-e409f0144165"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14858-L14874"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "28ad7e9c75a701425003cde4a7eb10fa471394628cd5004412778d8d7cddb50b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "pioneersoft" and pe.signatures[i].serial=="08:aa:a0:69:e9:25:17:f2:1c:e6:7c:a7:13:f6:ea:63" and 1368403200<=pe.signatures[i].not_after)
}
