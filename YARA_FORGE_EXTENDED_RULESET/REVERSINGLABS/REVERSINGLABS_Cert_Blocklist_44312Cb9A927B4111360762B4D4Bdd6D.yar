import "pe"

rule REVERSINGLABS_Cert_Blocklist_44312Cb9A927B4111360762B4D4Bdd6D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9bc1a8f4-36b7-52bd-9a65-fcd8ec2acf92"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15702-L15718"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8e34636ed815812af478dd01eacd5298fa2cfeb420ee2f45e055f557534cae71"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BEAR ADAMS CONSULTING LIMITED" and pe.signatures[i].serial=="44:31:2c:b9:a9:27:b4:11:13:60:76:2b:4d:4b:dd:6d" and 1554768000<=pe.signatures[i].not_after)
}
