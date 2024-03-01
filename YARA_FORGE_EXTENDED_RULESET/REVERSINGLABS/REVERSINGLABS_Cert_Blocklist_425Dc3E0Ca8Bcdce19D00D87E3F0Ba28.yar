import "pe"

rule REVERSINGLABS_Cert_Blocklist_425Dc3E0Ca8Bcdce19D00D87E3F0Ba28 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "df6e1403-c300-5d97-b57d-dc70d61b2229"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12218-L12234"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "67a975f2806825bf0da27fcaf33c2ff497fe9bb2af12c22ff505b49070516960"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Protover LLC" and pe.signatures[i].serial=="42:5d:c3:e0:ca:8b:cd:ce:19:d0:0d:87:e3:f0:ba:28" and 1621900800<=pe.signatures[i].not_after)
}
