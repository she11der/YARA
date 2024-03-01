import "pe"

rule REVERSINGLABS_Cert_Blocklist_Da000D18949C247D4Ddfc2585Cc8Bd0F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3e939b73-abe4-5941-93ab-18bcde854aaf"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3506-L3524"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3453f13e633a2c233f78d0389c655bb5304e567407b3e0c5c47e5e7127c345ca"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PORT-SERVIS LTD" and (pe.signatures[i].serial=="00:da:00:0d:18:94:9c:24:7d:4d:df:c2:58:5c:c8:bd:0f" or pe.signatures[i].serial=="da:00:0d:18:94:9c:24:7d:4d:df:c2:58:5c:c8:bd:0f") and 1564444800<=pe.signatures[i].not_after)
}
