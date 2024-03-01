rule SIGNATURE_BASE_APT_WEBSHELL_Tiny_Webshell : APT Hafnium WebShell FILE
{
	meta:
		description = "Detects WebShell Injection"
		author = "Markus Neis,Swisscom"
		id = "aa2fcecc-4c8b-570d-a81a-5dfb16c04e05"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_hafnium.yar#L67-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "099c8625c58b315b6c11f5baeb859f4c"
		logic_hash = "9309f9b57353b6fe292048d00794699a8637a3e6e429c562fb36c7e459003a3b"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "<%@ Page Language=\"Jscript\" Debug=true%>"
		$s1 = "=Request.Form(\""
		$s2 = "eval("

	condition:
		filesize <300 and all of ($s*) and $x1
}
