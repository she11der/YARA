import "pe"

rule REVERSINGLABS_Cert_Blocklist_3223B4616C2687C04865Bee8321726A8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "089aae56-4f46-563c-800a-dbf57db2bde6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5214-L5230"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fcb0a14866b3612c5ec5a7db7a3333e20a4605695b3d019eef84de85d7b3ea4d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and pe.signatures[i].serial=="32:23:b4:61:6c:26:87:c0:48:65:be:e8:32:17:26:a8" and 1601337600<=pe.signatures[i].not_after)
}
