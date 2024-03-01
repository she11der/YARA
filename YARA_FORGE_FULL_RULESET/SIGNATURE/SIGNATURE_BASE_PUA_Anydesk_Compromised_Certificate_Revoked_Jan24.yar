import "pe"

rule SIGNATURE_BASE_PUA_Anydesk_Compromised_Certificate_Revoked_Jan24 : FILE
{
	meta:
		description = "Detects binaries signed with a compromised signing certificate of AnyDesk (philandro Software GmbH, 0DBF152DEAF0B981A8A938D53F769DB8) after it was revoked. This is not a threat detection. It detects an outdated version of AnyDesk that was signed with a certificate that has been revoked."
		author = "Florian Roth"
		id = "eeefc9a5-1416-544b-b95e-c063000a4028"
		date = "2024-02-05"
		modified = "2024-02-05"
		reference = "https://anydesk.com/en/public-statement"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_anydesk_compromised_cert_feb23.yar#L3-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a1f148dbf15579bd6a65e7c93fa64f00ea481d6b314a444fa924a4604adb9a6d"
		score = 50
		quality = 85
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and pe.signatures[i].serial=="0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8")
}
