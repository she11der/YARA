rule SIGNATURE_BASE_CN_Honker_Webshell_Interception3389_Get : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file get.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "b17a793f-ffb7-5cdc-ba21-b0e2f0d14490"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L110-L126"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ceb6306f6379c2c1634b5058e1894b43abcf0296"
		logic_hash = "649e611c9d8948e60811af4209d737b3e797e6b42beba42439541ae543b062d6"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "userip = Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\")" fullword ascii
		$s1 = "file.writeline  szTime + \" HostName:\" + szhostname + \" IP:\" + userip+\":\"+n" ascii
		$s3 = "set file=fs.OpenTextFile(server.MapPath(\"WinlogonHack.txt\"),8,True)" fullword ascii

	condition:
		filesize <3KB and all of them
}
