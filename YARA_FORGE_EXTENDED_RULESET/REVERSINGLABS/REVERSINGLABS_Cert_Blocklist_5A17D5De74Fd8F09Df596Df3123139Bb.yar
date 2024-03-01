import "pe"

rule REVERSINGLABS_Cert_Blocklist_5A17D5De74Fd8F09Df596Df3123139Bb : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4a3ffa4a-c080-5d76-9655-010cde091ae2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8548-L8564"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7ed62740fe191d961ad32b2a79463cc9cbce557ea757e413860f7b4974904c03"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ACTA FIS d.o.o." and pe.signatures[i].serial=="5a:17:d5:de:74:fd:8f:09:df:59:6d:f3:12:31:39:bb" and 1611273600<=pe.signatures[i].not_after)
}
