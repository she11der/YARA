import "pe"

rule REVERSINGLABS_Cert_Blocklist_525B5529Db20D17A85Be284D6B7952Ea : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "52cdf082-7212-53e6-9e55-b86153e6afe8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17200-L17216"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8fd406004b634e4826659b1dff88c61074fd321969b9fd63ea45d8e9608b35f1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Buster Ind Com Imp e Exp de Acessorios P Autos Ltda" and pe.signatures[i].serial=="52:5b:55:29:db:20:d1:7a:85:be:28:4d:6b:79:52:ea" and 1508198400<=pe.signatures[i].not_after)
}
