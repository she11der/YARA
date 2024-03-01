rule SIGNATURE_BASE_WEBSHELL_Mailbox_Export_PST_Proxyshell_Aug26 : FILE
{
	meta:
		description = "Webshells generated by an Mailbox export to PST and stored as aspx: 570221043.aspx 689193944.aspx luifdecggoqmansn.aspx"
		author = "Moritz Oettle"
		id = "6aea414f-d27c-5202-84f8-b8620782fc90"
		date = "2021-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/hvs-consulting/ioc_signatures/tree/main/Proxyshell"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/expl_proxyshell.yar#L148-L174"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "07acbf74a4bf169fc128cd085759f33e89917e217703b3c6557ba5f954822fd4"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "!BDN"
		$g1 = "Page language=" ascii
		$g2 = "<%@ Page" ascii
		$g3 = "Request.Item[" ascii
		$g4 = "\"unsafe\");" ascii
		$g5 = "<%eval(" ascii
		$g6 = "script language=" ascii
		$g7 = "Request[" ascii
		$s1 = "gold8899" ascii
		$s2 = "exec_code" ascii
		$s3 = "orangenb" ascii

	condition:
		filesize <500KB and $x1 at 0 and (1 of ($s*) or 3 of ($g*))
}