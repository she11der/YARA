rule SIGNATURE_BASE_Webshell_Browser_201_3_Ma_Ma2_Download
{
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3141-L3162"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3b8bb6ca2eb146f8c170d629612ba12d4663445d443b681f2859af25d50ab6fe"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash4 = "4b45715fa3fa5473640e17f49ef5513d"
		hash5 = "fa87bbd7201021c1aefee6fcc5b8e25a"

	strings:
		$s1 = "private static final int EDITFIELD_ROWS = 30;" fullword
		$s2 = "private static String tempdir = \".\";" fullword
		$s6 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\""

	condition:
		2 of them
}
