import "pe"

rule SIGNATURE_BASE_HKTL_LNX_Pnscan : FILE
{
	meta:
		description = "Detects Pnscan port scanner"
		author = "Florian Roth (Nextron Systems)"
		id = "46c6c0d9-08bb-5de3-ad14-c1a7ab0542c6"
		date = "2019-05-27"
		modified = "2023-12-05"
		reference = "https://github.com/ptrrkssn/pnscan"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L4634-L4647"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "46a064f9df9d0a0f3fad4ec7be70b1e42074e5e117f7403d8239bc725590f268"
		score = 55
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "-R<hex list>   Hex coded response string to look for." fullword ascii
		$x2 = "This program implements a multithreaded TCP port scanner." ascii wide

	condition:
		filesize <6000KB and 1 of them
}
