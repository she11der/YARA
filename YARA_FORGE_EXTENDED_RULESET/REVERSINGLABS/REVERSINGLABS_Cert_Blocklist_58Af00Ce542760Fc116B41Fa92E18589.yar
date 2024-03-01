import "pe"

rule REVERSINGLABS_Cert_Blocklist_58Af00Ce542760Fc116B41Fa92E18589 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bb58ae8d-ef28-5644-abe8-2d4d8c892e95"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10770-L10786"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0ff773d252e5e0402171ae15d7ab43bcfd313eb8c326ed5f128a89ec43386a52"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DICKIE MUSDALE WINDFARM LIMITED" and pe.signatures[i].serial=="58:af:00:ce:54:27:60:fc:11:6b:41:fa:92:e1:85:89" and 1654819200<=pe.signatures[i].not_after)
}
