rule SIGNATURE_BASE_CN_Honker_Webshell_ASPX_Aspx3 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx3.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "4f835136-744a-5324-a1f4-02d1cfa2cab6"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L825-L840"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "dd61481771f67d9593214e605e63b62d5400c72f"
		logic_hash = "11bf511ee70ff4bde0a9320cb80dd9efa0f437d432c78a859153cfcc8e80db01"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m" ascii
		$s12 = "if (_Debug) System.Console.WriteLine(\"\\ninserting filename into CDS:" ascii

	condition:
		filesize <100KB and all of them
}
