import "pe"

rule REVERSINGLABS_Cert_Blocklist_41Bd49Bb456644D8183B3Dae72Ec8F22 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4645eeae-2aea-59aa-a6bf-095bb9d0d711"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15628-L15644"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0516af7b27d244f21c9cea62fe599725d412e385e34f5f3f4f618d565365d321"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="41:bd:49:bb:45:66:44:d8:18:3b:3d:ae:72:ec:8f:22" and 1468454400<=pe.signatures[i].not_after)
}
