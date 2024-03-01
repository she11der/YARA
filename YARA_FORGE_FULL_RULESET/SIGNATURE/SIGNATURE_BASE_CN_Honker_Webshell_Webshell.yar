rule SIGNATURE_BASE_CN_Honker_Webshell_Webshell : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file WebShell.cgi"
		author = "Florian Roth (Nextron Systems)"
		id = "9fe4c8fd-3955-5405-add2-835e6f64e8f2"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L1119-L1135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7ef773df7a2f221468cc8f7683e1ace6b1e8139a"
		logic_hash = "7d80390a86b1858d2cf4f2be56df7e734aea402de0878adf40ef36721719ca74"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$login = crypt($WebShell::Configuration::password, $salt);" fullword ascii
		$s2 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword ascii
		$s3 = "warn \"command: '$command'\\n\";" fullword ascii

	condition:
		filesize <30KB and 2 of them
}
