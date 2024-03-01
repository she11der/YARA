rule SIGNATURE_BASE_CN_Honker_Webshell_ASP_Web_Asp : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file web.asp.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "67e03591-770a-5b32-9579-c899894740fc"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L388-L403"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "aebf6530e89af2ad332062c6aae4a8ca91517c76"
		logic_hash = "5d2d7e6b9340ee4fd845ff05c99526c919214974b1a0def66492fe3cd4a75fe9"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<FORM method=post target=_blank>ShellUrl: <INPUT " fullword ascii
		$s1 = "\" >[Copy code]</a> 4ngr7&nbsp; &nbsp;</td>" fullword ascii

	condition:
		filesize <13KB and all of them
}
