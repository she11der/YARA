rule SIGNATURE_BASE_Webshell_201_3_Ma_Download
{
	meta:
		description = "Web Shell - from files 201.jsp, 3.jsp, ma.jsp, download.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L2361-L2380"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "14eccd07e7bef9d570f75fc4adc204d175dcfbb5b950bdb3e25a65d3c5bb0310"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "a7e25b8ac605753ed0c438db93f6c498"
		hash1 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash2 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash3 = "fa87bbd7201021c1aefee6fcc5b8e25a"

	strings:
		$s0 = "<input title=\"Upload selected file to the current working directory\" type=\"Su"
		$s5 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but"
		$s6 = "<input title=\"Delete all selected files and directories incl. subdirs\" class="

	condition:
		all of them
}
