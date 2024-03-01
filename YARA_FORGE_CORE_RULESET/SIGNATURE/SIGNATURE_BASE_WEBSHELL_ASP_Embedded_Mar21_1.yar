rule SIGNATURE_BASE_WEBSHELL_ASP_Embedded_Mar21_1 : FILE
{
	meta:
		description = "Detects ASP webshells"
		author = "Florian Roth (Nextron Systems)"
		id = "7cf7db9d-8f8a-51db-a0e6-84748e8f9e1f"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_hafnium.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "4a8b4cea6f53dad9771cb694ec55f305f04dfdbd8e663154cad672ca414c138c"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "<script runat=\"server\">" nocase
		$s2 = "new System.IO.StreamWriter(Request.Form["
		$s3 = ".Write(Request.Form["

	condition:
		filesize <100KB and all of them
}
