import "pe"

rule REVERSINGLABS_Cert_Blocklist_7D20Dec3797A1Ac30649Ebb184265B79 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5344bda2-bc11-5700-a0f7-52792c5bb87a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14404-L14420"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "78c0575a1c9ecf37ef5bac0612c20f96b8641875b0ba786979adc8a77f001a5e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jiang Liu" and pe.signatures[i].serial=="7d:20:de:c3:79:7a:1a:c3:06:49:eb:b1:84:26:5b:79" and 1474156800<=pe.signatures[i].not_after)
}
