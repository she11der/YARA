rule SIGNATURE_BASE_CN_Honker_Webshell_JSP_Jsp : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jsp.html"
		author = "Florian Roth (Nextron Systems)"
		id = "46f2fb10-2c0c-5bc2-b3bb-eba4c74bcad7"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L213-L228"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c58fed3d3d1e82e5591509b04ed09cb3675dc33a"
		logic_hash = "089e1a553900d149a4087ac81254295d74de15d9baaf73e60ce4f061e450e8c7"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<input name=f size=30 value=shell.jsp>" fullword ascii
		$s2 = "<font color=red>www.i0day.com  By:" fullword ascii

	condition:
		filesize <3KB and all of them
}
