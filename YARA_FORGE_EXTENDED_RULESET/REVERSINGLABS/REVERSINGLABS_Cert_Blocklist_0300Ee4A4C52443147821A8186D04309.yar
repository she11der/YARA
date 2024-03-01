import "pe"

rule REVERSINGLABS_Cert_Blocklist_0300Ee4A4C52443147821A8186D04309 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "abccf84f-ba18-5644-897c-d23a228facff"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13512-L13528"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8476ece98427c1ffd99d820c25fe664397de2c393473f7d5ee0846d8d840fd9e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Buster Ind Com Imp e Exp de Acessorios P Autos Ltda" and pe.signatures[i].serial=="03:00:ee:4a:4c:52:44:31:47:82:1a:81:86:d0:43:09" and 1494892800<=pe.signatures[i].not_after)
}
