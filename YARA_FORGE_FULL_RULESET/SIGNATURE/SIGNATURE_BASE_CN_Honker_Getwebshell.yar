rule SIGNATURE_BASE_CN_Honker_Getwebshell : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetWebShell.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "919883f4-af66-5d07-ad41-8cba3e049396"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L913-L930"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b63b53259260a7a316932c0a4b643862f65ee9f8"
		logic_hash = "5d6638596607884950e702144416eb6fd3b009c88e4af5f81a50f346d7491c95"
		score = 70
		quality = 60
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "echo P.Open \"GET\",\"http://www.baidu.com/ma.exe\",0 >>run.vbs" fullword ascii
		$s5 = "http://127.0.0.1/sql.asp?id=1" fullword wide
		$s14 = "net user admin$ hack /add" fullword wide
		$s15 = ";Drop table [hack];create table [dbo].[hack] ([cmd] [image])--" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <70KB and 1 of them
}
