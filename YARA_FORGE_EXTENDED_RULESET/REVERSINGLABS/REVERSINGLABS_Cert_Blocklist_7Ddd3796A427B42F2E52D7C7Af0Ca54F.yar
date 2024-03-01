import "pe"

rule REVERSINGLABS_Cert_Blocklist_7Ddd3796A427B42F2E52D7C7Af0Ca54F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5c2e1f5b-5ff7-51d7-9642-0a527856814c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7350-L7366"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "804ab8c44e5d97d8e14f852d61094e90d1e3ace66316781e9e79ab46fc7db8e7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Fobos" and pe.signatures[i].serial=="7d:dd:37:96:a4:27:b4:2f:2e:52:d7:c7:af:0c:a5:4f" and 1612915200<=pe.signatures[i].not_after)
}
