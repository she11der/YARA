rule SIGNATURE_BASE_SUSP_Excel_IQY_Remoteuri_Syntax : FILE
{
	meta:
		description = "Detects files with Excel IQY RemoteURI syntax"
		author = "Nick Carr"
		id = "ea3427da-9cce-5ad9-9c78-e3cee802ba80"
		date = "2018-08-17"
		modified = "2023-11-25"
		reference = "https://twitter.com/ItsReallyNick/status/1030330473954897920"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_office_dropper.yar#L102-L120"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7033b0a4226dd289ecc670a0807e4159dd4486f52bc80a6b5ddd34d6961ab163"
		score = 55
		quality = 85
		tags = "FILE"

	strings:
		$URL = "http"
		$fp1 = "https://go.microsoft.com"

	condition:
		uint32(0)==0x0d424557 and uint32(4)==0x0a0d310a and filesize <1MB and $URL and not 1 of ($fp*)
}
