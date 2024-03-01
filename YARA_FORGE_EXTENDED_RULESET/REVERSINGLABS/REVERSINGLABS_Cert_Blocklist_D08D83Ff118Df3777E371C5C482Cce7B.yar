import "pe"

rule REVERSINGLABS_Cert_Blocklist_D08D83Ff118Df3777E371C5C482Cce7B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5acd2e61-1c04-5cc5-8773-25856fc163c4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16156-L16174"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5fdaf01c6a23057ab976e3ad2a8b40558b16693161410b0f30d7b884de7e3985"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMO-K Limited Liability Company" and (pe.signatures[i].serial=="00:d0:8d:83:ff:11:8d:f3:77:7e:37:1c:5c:48:2c:ce:7b" or pe.signatures[i].serial=="d0:8d:83:ff:11:8d:f3:77:7e:37:1c:5c:48:2c:ce:7b") and 1444780800<=pe.signatures[i].not_after)
}
