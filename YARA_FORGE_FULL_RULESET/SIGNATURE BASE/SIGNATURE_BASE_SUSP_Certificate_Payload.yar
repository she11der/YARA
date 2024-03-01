rule SIGNATURE_BASE_SUSP_Certificate_Payload : FILE
{
	meta:
		description = "Detects payloads that pretend to be certificates"
		author = "Didier Stevens, Florian Roth"
		id = "6f1fe410-591a-5a59-a683-67cad9777dfe"
		date = "2018-08-02"
		modified = "2023-12-05"
		reference = "https://blog.nviso.be/2018/08/02/powershell-inside-a-certificate-part-3/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cert_payloads.yar#L1-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "909cf4209bbb876a042d86e017f65ce3764d2fde7a602406ed8531ba97c9fb9b"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$re1 = "-----BEGIN CERTIFICATE-----"
		$fp1 = "replace it with the PEM-encoded root certificate"

	condition:
		uint32(0)==0x2D2D2D2D and $re1 at 0 and not uint8(29)==0x4D and not uint8(28)==0x4D and not 1 of ($fp*)
}
