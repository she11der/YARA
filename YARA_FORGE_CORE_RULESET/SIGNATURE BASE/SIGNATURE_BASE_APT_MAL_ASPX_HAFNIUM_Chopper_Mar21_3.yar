rule SIGNATURE_BASE_APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_3 : FILE
{
	meta:
		description = "Detects HAFNIUM ASPX files dropped on compromised servers"
		author = "Florian Roth (Nextron Systems)"
		id = "9c2ba123-63c4-5e9c-a08f-bd9db3304691"
		date = "2021-03-07"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_hafnium.yar#L202-L216"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "391b366d78c2f24dc006a5365ec232a9a3c2fe0ea514b18897701ceeffcc81ca"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "runat=\"server\">void Page_Load(object" ascii wide
		$s2 = "Request.Files[0].SaveAs(Server.MapPath(" ascii wide

	condition:
		filesize <50KB and all of them
}
