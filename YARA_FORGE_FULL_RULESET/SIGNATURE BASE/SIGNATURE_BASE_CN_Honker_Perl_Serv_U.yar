rule SIGNATURE_BASE_CN_Honker_Perl_Serv_U : FILE
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file Perl-serv-U.pl"
		author = "Florian Roth (Nextron Systems)"
		id = "d793227d-dd4d-5c92-bfdc-9662c3ed8933"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_scripts.yar#L48-L63"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f333c597ff746ebd5a641fbc248497d61e3ec17b"
		logic_hash = "deb4ee54f9127bc093f96f7dbf3633fbfc3f66358c76fb15928dabbbffdd4963"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$dir = 'C:\\\\WINNT\\\\System32\\\\';" fullword ascii
		$s2 = "$sock = IO::Socket::INET->new(\"127.0.0.1:$adminport\") || die \"fail\";" fullword ascii

	condition:
		filesize <8KB and all of them
}
